# Struttura file principale app.py

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os
from datetime import datetime, timedelta
import threading
import time
from pysnmp.hlapi import *
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///snmpmonitor.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Modelli database
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

class Template(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(200))
    oids = db.Column(db.Text, nullable=False)  # JSON con OID da monitorare
    check_interval = db.Column(db.Integer, default=300)  # in secondi
    hosts = db.relationship('Host', backref='template', lazy=True)

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(200))
    hosts = db.relationship('Host', backref='group', lazy=True)

class Host(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(50), nullable=False)
    ip_address = db.Column(db.String(15), nullable=False)
    snmp_community = db.Column(db.String(50), default='public')
    snmp_port = db.Column(db.Integer, default=161)
    template_id = db.Column(db.Integer, db.ForeignKey('template.id'), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    status = db.Column(db.String(20), default='unknown')
    last_check = db.Column(db.DateTime)
    metrics = db.relationship('Metric', backref='host', lazy=True, cascade="all, delete-orphan")

class Metric(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey('host.id'), nullable=False)
    oid = db.Column(db.String(100), nullable=False)
    oid_name = db.Column(db.String(100))
    value = db.Column(db.String(200))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey('host.id'), nullable=False)
    message = db.Column(db.String(200), nullable=False)
    severity = db.Column(db.String(20), default='warning')
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    acknowledged = db.Column(db.Boolean, default=False)
    host = db.relationship('Host', backref=db.backref('alerts', lazy=True))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# SNMP Monitoring Thread
def snmp_monitor():
    while True:
        with app.app_context():
            hosts = Host.query.all()
            for host in hosts:
                try:
                    template = Template.query.get(host.template_id)
                    oids = json.loads(template.oids)
                    
                    for oid_name, oid in oids.items():
                        errorIndication, errorStatus, errorIndex, varBinds = next(
                            getCmd(SnmpEngine(),
                                  CommunityData(host.snmp_community, mpModel=1),  # mpModel=1 per SNMPv2c
                                  UdpTransportTarget((host.ip_address, host.snmp_port)),
                                  ContextData(),
                                  ObjectType(ObjectIdentity(oid)))
                        )
                        
                        if errorIndication:
                            host.status = 'error'
                            new_alert = Alert(
                                host_id=host.id,
                                message=f"SNMP Error: {errorIndication}",
                                severity='critical'
                            )
                            db.session.add(new_alert)
                            break
                        elif errorStatus:
                            host.status = 'error'
                            new_alert = Alert(
                                host_id=host.id,
                                message=f"SNMP Error: {errorStatus.prettyPrint()} at {errorIndex and varBinds[int(errorIndex) - 1][0] or '?'}",
                                severity='critical'
                            )
                            db.session.add(new_alert)
                            break
                        else:
                            # Aggiornamento metrica
                            for varBind in varBinds:
                                value = str(varBind[1])
                                
                                # Controlla se esiste già una metrica per questo OID
                                metric = Metric.query.filter_by(host_id=host.id, oid=oid).first()
                                if metric:
                                    metric.value = value
                                    metric.timestamp = datetime.utcnow()
                                else:
                                    new_metric = Metric(
                                        host_id=host.id,
                                        oid=oid,
                                        oid_name=oid_name,
                                        value=value
                                    )
                                    db.session.add(new_metric)
                    
                    host.status = 'up'
                    host.last_check = datetime.utcnow()
                
                except Exception as e:
                    host.status = 'error'
                    new_alert = Alert(
                        host_id=host.id,
                        message=f"Exception: {str(e)}",
                        severity='critical'
                    )
                    db.session.add(new_alert)
            
            db.session.commit()
        
        time.sleep(60)  # Controlla ogni minuto quale host deve essere verificato

# Avvio thread monitoraggio
monitor_thread = threading.Thread(target=snmp_monitor, daemon=True)

# Routes per l'interfaccia web
@app.route('/')
@login_required
def dashboard():
    groups = Group.query.all()
    hosts_by_status = {
        'up': Host.query.filter_by(status='up').count(),
        'error': Host.query.filter_by(status='error').count(),
        'unknown': Host.query.filter_by(status='unknown').count()
    }
    recent_alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(5).all()
    return render_template('dashboard.html', groups=groups, hosts_by_status=hosts_by_status, recent_alerts=recent_alerts)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.password == password:  # In produzione usare password criptate
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Host management
@app.route('/hosts')
@login_required
def hosts():
    hosts = Host.query.all()
    return render_template('hosts.html', hosts=hosts)

@app.route('/hosts/add', methods=['GET', 'POST'])
@login_required
def add_host():
    if request.method == 'POST':
        hostname = request.form.get('hostname')
        ip_address = request.form.get('ip_address')
        snmp_community = request.form.get('snmp_community')
        snmp_port = int(request.form.get('snmp_port', 161))
        template_id = int(request.form.get('template_id'))
        group_id = int(request.form.get('group_id'))
        
        new_host = Host(
            hostname=hostname,
            ip_address=ip_address,
            snmp_community=snmp_community,
            snmp_port=snmp_port,
            template_id=template_id,
            group_id=group_id
        )
        
        db.session.add(new_host)
        db.session.commit()
        flash('Host added successfully')
        return redirect(url_for('hosts'))
    
    templates = Template.query.all()
    groups = Group.query.all()
    return render_template('add_host.html', templates=templates, groups=groups)

@app.route('/hosts/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_host(id):
    host = Host.query.get_or_404(id)
    
    if request.method == 'POST':
        host.hostname = request.form.get('hostname')
        host.ip_address = request.form.get('ip_address')
        host.snmp_community = request.form.get('snmp_community')
        host.snmp_port = int(request.form.get('snmp_port', 161))
        host.template_id = int(request.form.get('template_id'))
        host.group_id = int(request.form.get('group_id'))
        
        db.session.commit()
        flash('Host updated successfully')
        return redirect(url_for('hosts'))
    
    templates = Template.query.all()
    groups = Group.query.all()
    return render_template('edit_host.html', host=host, templates=templates, groups=groups)

@app.route('/hosts/delete/<int:id>', methods=['POST'])
@login_required
def delete_host(id):
    host = Host.query.get_or_404(id)
    db.session.delete(host)
    db.session.commit()
    flash('Host deleted successfully')
    return redirect(url_for('hosts'))

# Template management
@app.route('/templates')
@login_required
def templates():
    templates = Template.query.all()
    return render_template('templates.html', templates=templates)

@app.route('/templates/add', methods=['GET', 'POST'])
@login_required
def add_template():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        oids = request.form.get('oids')  # JSON con formato {"nome": "OID"}
        check_interval = int(request.form.get('check_interval', 300))
        
        new_template = Template(
            name=name,
            description=description,
            oids=oids,
            check_interval=check_interval
        )
        
        db.session.add(new_template)
        db.session.commit()
        flash('Template added successfully')
        return redirect(url_for('templates'))
    
    return render_template('add_template.html')

@app.route('/templates/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_template(id):
    template = Template.query.get_or_404(id)
    
    if request.method == 'POST':
        template.name = request.form.get('name')
        template.description = request.form.get('description')
        template.oids = request.form.get('oids')
        template.check_interval = int(request.form.get('check_interval', 300))
        
        db.session.commit()
        flash('Template updated successfully')
        return redirect(url_for('templates'))
    
    return render_template('edit_template.html', template=template)

@app.route('/templates/delete/<int:id>', methods=['POST'])
@login_required
def delete_template(id):
    template = Template.query.get_or_404(id)
    
    # Verifica se ci sono host che utilizzano questo template
    if Host.query.filter_by(template_id=id).first():
        flash('Cannot delete template as it is being used by one or more hosts')
        return redirect(url_for('templates'))
    
    db.session.delete(template)
    db.session.commit()
    flash('Template deleted successfully')
    return redirect(url_for('templates'))

# Group management
@app.route('/groups')
@login_required
def groups():
    groups = Group.query.all()
    return render_template('groups.html', groups=groups)

@app.route('/groups/add', methods=['GET', 'POST'])
@login_required
def add_group():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        
        new_group = Group(
            name=name,
            description=description
        )
        
        db.session.add(new_group)
        db.session.commit()
        flash('Group added successfully')
        return redirect(url_for('groups'))
    
    return render_template('add_group.html')

@app.route('/groups/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_group(id):
    group = Group.query.get_or_404(id)
    
    if request.method == 'POST':
        group.name = request.form.get('name')
        group.description = request.form.get('description')
        
        db.session.commit()
        flash('Group updated successfully')
        return redirect(url_for('groups'))
    
    return render_template('edit_group.html', group=group)

@app.route('/groups/delete/<int:id>', methods=['POST'])
@login_required
def delete_group(id):
    group = Group.query.get_or_404(id)
    
    # Verifica se ci sono host in questo gruppo
    if Host.query.filter_by(group_id=id).first():
        flash('Cannot delete group as it contains one or more hosts')
        return redirect(url_for('groups'))
    
    db.session.delete(group)
    db.session.commit()
    flash('Group deleted successfully')
    return redirect(url_for('groups'))

# Alerts management
@app.route('/alerts')
@login_required
def alerts():
    alerts = Alert.query.order_by(Alert.timestamp.desc()).all()
    return render_template('alerts.html', alerts=alerts)

@app.route('/alerts/acknowledge/<int:id>', methods=['POST'])
@login_required
def acknowledge_alert(id):
    alert = Alert.query.get_or_404(id)
    alert.acknowledged = True
    db.session.commit()
    flash('Alert acknowledged')
    return redirect(url_for('alerts'))

# API per grafici e dashboard
@app.route('/api/metrics/<int:host_id>')
@login_required
def get_host_metrics(host_id):
    host = Host.query.get_or_404(host_id)
    metrics = []
    
    for metric in host.metrics:
        metrics.append({
            'oid': metric.oid,
            'oid_name': metric.oid_name,
            'value': metric.value,
            'timestamp': metric.timestamp.isoformat()
        })
    
    return jsonify(metrics)

@app.route('/api/host_status')
@login_required
def get_host_status():
    hosts = Host.query.all()
    status_data = []
    
    for host in hosts:
        status_data.append({
            'id': host.id,
            'hostname': host.hostname,
            'ip_address': host.ip_address,
            'status': host.status,
            'last_check': host.last_check.isoformat() if host.last_check else None,
            'group': host.group.name,
            'template': host.template.name
        })
    
    return jsonify(status_data)

# Inizializzazione DB e avvio thread
@app.before_first_request
def initialize():
    db.create_all()
    
    # Crea utente admin se non esiste
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', password='admin')  # In produzione usare password criptate
        db.session.add(admin)
        
        # Crea un gruppo e template predefiniti
        default_group = Group(name='Default', description='Default group')
        default_template = Template(
            name='Basic SNMP',
            description='Basic SNMP monitoring template',
            oids=json.dumps({
                'sysDescr': '1.3.6.1.2.1.1.1.0',
                'sysUptime': '1.3.6.1.2.1.1.3.0',
                'sysName': '1.3.6.1.2.1.1.5.0'
            })
        )
        
        db.session.add(default_group)
        db.session.add(default_template)
        db.session.commit()
    
    # Avvia il thread di monitoraggio se non è già in esecuzione
    if not monitor_thread.is_alive():
        monitor_thread.start()

if __name__ == '__main__':
    app.run(debug=True)
