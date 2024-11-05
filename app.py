from flask import Flask, render_template, request, redirect, session, url_for, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, send
from werkzeug.security import generate_password_hash, check_password_hash
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import uuid
import io

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///techmonium.db'
db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*")

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    alert_message = db.Column(db.String(200), nullable=True)
    subscription_plan = db.Column(db.String(200), nullable=True)
    order_history = db.Column(db.Text, nullable=True)
    one_time_token = db.Column(db.String(200), nullable=True)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

class Request(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    plan = db.Column(db.String(200), nullable=False)

@app.route('/')
def index():
    if 'username' in session:
        user = User.query.filter_by(username=session['username']).first()
        return render_template('user_hub.html', username=session['username'], user=user)
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['username'] = username
            return redirect('/')
        return 'Invalid username or password'
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect('/login')

@app.route('/admin/manage_users', methods=['GET', 'POST'])
def manage_users():
    if 'username' not in session or not User.query.filter_by(username=session['username'], is_admin=True).first():
        return redirect('/login')
    if request.method == 'POST':
        action = request.form['action']
        if action == 'create_user':
            username = request.form['username']
            password = request.form['password']
            email = request.form['email']
            is_admin = 'is_admin' in request.form
            if User.query.filter_by(username=username).first():
                flash('Username already exists.')
            elif User.query.filter_by(email=email).first():
                flash('Email already exists.')
            else:
                new_user = User(username=username, email=email, is_admin=is_admin)
                new_user.set_password(password)
                db.session.add(new_user)
                db.session.commit()
                flash('User created successfully.')
        else:
            user_id = request.form['user_id']
            user = User.query.get(user_id)
            if action == 'delete':
                db.session.delete(user)
                db.session.commit()
            elif action == 'update_password':
                new_password = request.form['new_password']
                user.set_password(new_password)
                db.session.commit()
            elif action == 'send_alert':
                alert_message = request.form['alert_message']
                user.alert_message = alert_message
                db.session.commit()
            elif action == 'grant_admin':
                user.is_admin = True
                db.session.commit()
            elif action == 'revoke_admin':
                user.is_admin = False
                db.session.commit()
            elif action == 'mark_purchased':
                subscription_plan = request.form['subscription_plan']
                user.subscription_plan = subscription_plan
                user.order_history = (user.order_history or '') + f'\nPurchased: {subscription_plan}'
                db.session.commit()
    users = User.query.all()
    return render_template('manage_users.html', users=users, user=session['username'])

@app.route('/admin/manage_user/<int:user_id>', methods=['GET', 'POST'])
def manage_user(user_id):
    if 'username' not in session or not User.query.filter_by(username=session['username'], is_admin=True).first():
        return redirect('/login')
    user = User.query.get(user_id)
    if request.method == 'POST':
        action = request.form['action']
        if action == 'update_user':
            user.username = request.form['username']
            user.email = request.form['email']
            user.subscription_plan = request.form['subscription_plan']
            user.is_admin = 'is_admin' in request.form
            db.session.commit()
            flash('User updated successfully.')
        elif action == 'update_order_history':
            user.order_history = request.form['order_history']
            db.session.commit()
            flash('Order history updated successfully.')
    return render_template('manage_user.html', user=user)

@app.route('/admin/manage_content', methods=['GET', 'POST'])
def manage_content():
    if 'username' not in session or not User.query.filter_by(username=session['username'], is_admin=True).first():
        return redirect('/login')
    if request.method == 'POST':
        new_text = request.form['new_text']
        # Save the new text to a file or database
        with open('static/content.txt', 'w') as f:
            f.write(new_text)
    try:
        with open('static/content.txt', 'r') as f:
            current_text = f.read()
    except FileNotFoundError:
        current_text = ""
    return render_template('manage_content.html', current_text=current_text)

@app.route('/admin')
def admin_panel():
    if 'username' not in session or not User.query.filter_by(username=session['username'], is_admin=True).first():
        return redirect('/login')
    return render_template('admin.html')

@app.route('/subscriptions')
def subscriptions():
    plans = [
        {'name': 'Platinum Plan', 'price': '$20/month'},
        {'name': 'Family Plan', 'price': 'CONTACT SAM TO PURCHASE'},
    ]
    return render_template('subscriptions.html', plans=plans)

@app.route('/order_history')
def order_history():
    if 'username' in session:
        user = User.query.filter_by(username=session['username']).first()
        return render_template('order_history.html', order_history=user.order_history)
    return redirect('/login')

@app.route('/alert')
def alert():
    if 'username' in session:
        user = User.query.filter_by(username=session['username']).first()
        if user and user.alert_message:
            return render_template('alert.html', alert_message=user.alert_message)
    return redirect('/')

@app.route('/platinum_plan')
def platinum_plan():
    if 'username' in session:
        user = User.query.filter_by(username=session['username']).first()
        if user.subscription_plan == 'Platinum Plan':
            return render_template('platinum_plan.html')
    return redirect('/login')

@app.route('/family_plan')
def family_plan():
    if 'username' in session:
        user = User.query.filter_by(username=session['username']).first()
        if user.subscription_plan == 'Family Plan':
            return render_template('family_plan.html')
    return redirect('/login')

@app.route('/testing_plan')
def testing_plan():
    if 'username' in session:
        user = User.query.filter_by(username=session['username']).first()
        if user.subscription_plan == 'Testing Plan':
            return render_template('testing_plan.html')
    return redirect('/login')

@app.route('/employee')
def employee():
    if 'username' in session:
        user = User.query.filter_by(username=session['username']).first()
        if user.subscription_plan == 'Employee':
            return render_template('employee.html')
    return redirect('/login')

@app.route('/friend')
def friend():
    if 'username' in session:
        user = User.query.filter_by(username=session['username']).first()
        if user.subscription_plan == 'Friend':
            return render_template('friend.html')
    return redirect('/login')

@app.route('/cancel_request', methods=['POST'])
def cancel_request():
    if 'username' in session:
        user = User.query.filter_by(username=session['username']).first()
        plan = request.form['plan']
        new_request = Request(username=user.username, email=user.email, password=user.password, plan=plan)
        db.session.add(new_request)
        db.session.commit()
        flash('Cancellation request sent.')
    return redirect(url_for(user.subscription_plan.lower().replace(' ', '_')))

@app.route('/request_subscription', methods=['POST'])
def request_subscription():
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    plan = request.form['plan']
    new_request = Request(username=username, email=email, password=generate_password_hash(password), plan=plan)
    db.session.add(new_request)
    db.session.commit()
    flash('Subscription request sent.')
    return redirect(url_for('subscriptions'))

@app.route('/admin/view_requests')
def view_requests():
    if 'username' not in session or not User.query.filter_by(username=session['username'], is_admin=True).first():
        return redirect('/login')
    requests = Request.query.all()
    return render_template('view_requests.html', requests=requests)

@app.route('/admin/handle_request', methods=['POST'])
def handle_request():
    if 'username' not in session or not User.query.filter_by(username=session['username'], is_admin=True).first():
        return redirect('/login')
    request_id = request.form['request_id']
    action = request.form['action']
    req = Request.query.get(request_id)
    user = User.query.filter_by(username=req.username).first()
    if action == 'approve':
        if not user:
            user = User(username=req.username, email=req.email, password=req.password, subscription_plan=req.plan)
            user.one_time_token = str(uuid.uuid4())
            db.session.add(user)
        else:
            user.subscription_plan = req.plan
            user.order_history = (user.order_history or '') + f'\nPurchased: {req.plan}'
            user.one_time_token = str(uuid.uuid4())
        db.session.delete(req)
        db.session.commit()
        flash('Subscription request approved.')
        return redirect(f"mailto:{req.email}?subject=Subscription Approved&body=Your subscription request has been approved. Please set your password using the following link: {url_for('set_password', token=user.one_time_token, _external=True)}")
    elif action == 'deny':
        db.session.delete(req)
        db.session.commit()
        flash('Subscription request denied.')
        return redirect(f"mailto:{req.email}?subject=Subscription Denied&body=Unfortunately, your subscription request has been denied.")
    return redirect(url_for('view_requests'))

@app.route('/admin/generate_token', methods=['POST'])
def generate_token():
    if 'username' not in session or not User.query.filter_by(username=session['username'], is_admin=True).first():
        return redirect('/login')
    user_id = request.form['user_id']
    user = User.query.get(user_id)
    user.one_time_token = str(uuid.uuid4())
    db.session.commit()
    flash(f'One-time sign-in link: {url_for("one_time_sign_in", token=user.one_time_token, _external=True)}')
    return redirect(url_for('manage_users'))

@app.route('/one_time_sign_in/<token>')
def one_time_sign_in(token):
    user = User.query.filter_by(one_time_token=token).first()
    if user:
        session['username'] = user.username
        user.one_time_token = None
        db.session.commit()
        return redirect('/')
    return 'Invalid or expired token'

@app.route('/set_password/<token>', methods=['GET', 'POST'])
def set_password(token):
    user = User.query.filter_by(one_time_token=token).first()
    if not user:
        return 'Invalid or expired token'
    if request.method == 'POST':
        password = request.form['password']
        user.set_password(password)
        user.one_time_token = None
        db.session.commit()
        flash('Password set successfully. You can now log in.')
        return redirect(url_for('login'))
    return render_template('set_password.html', token=token)

@app.route('/admin/generate_invoice', methods=['GET', 'POST'])
def generate_invoice():
    if request.method == 'POST':
        user_id = request.form['user_id']
        user = User.query.get(user_id)
        items = request.form.getlist('items[]')
        prices = request.form.getlist('prices[]')
        discounts = request.form.getlist('discounts[]')
        buffer = io.BytesIO()
        p = canvas.Canvas(buffer, pagesize=letter)
        p.drawString(100, 750, "Techmonium")
        p.drawString(100, 730, f"Username: {user.username}")
        p.drawString(100, 710, f"Email: {user.email}")
        p.drawString(100, 690, f"Subscription Plan: {user.subscription_plan}")
        y = 670
        subtotal = 0
        for item, price, discount in zip(items, prices, discounts):
            price = float(price)
            discount = float(discount)
            net_price = price - discount
            subtotal += net_price
            p.drawString(100, y, f"Item: {item}, Price: ${price:.2f}, Discount: ${discount:.2f}, Net Price: ${net_price:.2f}")
            y -= 20
        tax = subtotal * 0.0635
        total = subtotal + tax
        p.drawString(100, y, f"Subtotal: ${subtotal:.2f}")
        y -= 20
        p.drawString(100, y, f"Tax (6.35%): ${tax:.2f}")
        y -= 20
        p.drawString(100, y, f"Total: ${total:.2f}")
        p.showPage()
        p.save()
        buffer.seek(0)
        return send_file(buffer, as_attachment=True, download_name=f"{user.username}_invoice.pdf", mimetype='application/pdf')
    else:
        users = User.query.all()
        return render_template('generate_invoice.html', users=users)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='sam').first():
            owner_user = User(username='sam', email='sam@example.com', is_admin=True)
            owner_user.set_password('10')
            db.session.add(owner_user)
            db.session.commit()
    socketio.run(app, host='0.0.0.0', port=5000)
    