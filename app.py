import os
import csv
import io
from datetime import datetime, date, timedelta
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, flash, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, DecimalField, DateField, SelectField, BooleanField
from wtforms.validators import DataRequired, Email, Length, Optional, NumberRange

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///crm.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# =============================================================================
# DATABASE MODELS
# =============================================================================

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    communications = db.relationship('Communication', backref='logged_by', lazy='dynamic')
    tasks = db.relationship('Task', backref='assigned_to', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Donor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120))
    phone = db.Column(db.String(20))
    address = db.Column(db.String(200))
    city = db.Column(db.String(100))
    state = db.Column(db.String(50))
    zip_code = db.Column(db.String(20))
    interests = db.Column(db.Text)
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    donations = db.relationship('Donation', backref='donor', lazy='dynamic', cascade='all, delete-orphan')
    communications = db.relationship('Communication', backref='donor', lazy='dynamic', cascade='all, delete-orphan')
    tasks = db.relationship('Task', backref='donor', lazy='dynamic', cascade='all, delete-orphan')

    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}"

    @property
    def total_donated(self):
        return sum(d.amount for d in self.donations) or 0

    @property
    def last_donation(self):
        return self.donations.order_by(Donation.date.desc()).first()


class Donation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    donor_id = db.Column(db.Integer, db.ForeignKey('donor.id'), nullable=False)
    amount = db.Column(db.Numeric(10, 2), nullable=False)
    date = db.Column(db.Date, nullable=False, default=date.today)
    donation_type = db.Column(db.String(50))  # one-time, recurring, in-kind
    campaign = db.Column(db.String(100))
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Communication(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    donor_id = db.Column(db.Integer, db.ForeignKey('donor.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comm_type = db.Column(db.String(50), nullable=False)  # email, phone, meeting, letter
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    subject = db.Column(db.String(200))
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    donor_id = db.Column(db.Integer, db.ForeignKey('donor.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    description = db.Column(db.String(500), nullable=False)
    due_date = db.Column(db.Date)
    completed = db.Column(db.Boolean, default=False)
    completed_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class DonorRelationship(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    donor_id = db.Column(db.Integer, db.ForeignKey('donor.id'), nullable=False)
    related_donor_id = db.Column(db.Integer, db.ForeignKey('donor.id'), nullable=False)
    relationship_type = db.Column(db.String(50))  # spouse, family, colleague, friend

    donor = db.relationship('Donor', foreign_keys=[donor_id], backref='relationships_from')
    related_donor = db.relationship('Donor', foreign_keys=[related_donor_id], backref='relationships_to')


# =============================================================================
# FORMS
# =============================================================================

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])


class RegisterForm(FlaskForm):
    name = StringField('Full Name', validators=[DataRequired(), Length(min=2, max=100)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])


class DonorForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired(), Length(max=50)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(max=50)])
    email = StringField('Email', validators=[Optional(), Email()])
    phone = StringField('Phone', validators=[Optional(), Length(max=20)])
    address = StringField('Address', validators=[Optional(), Length(max=200)])
    city = StringField('City', validators=[Optional(), Length(max=100)])
    state = StringField('State', validators=[Optional(), Length(max=50)])
    zip_code = StringField('ZIP Code', validators=[Optional(), Length(max=20)])
    interests = TextAreaField('Interests', validators=[Optional()])
    notes = TextAreaField('Notes', validators=[Optional()])


class DonationForm(FlaskForm):
    amount = DecimalField('Amount ($)', validators=[DataRequired(), NumberRange(min=0.01)])
    date = DateField('Date', validators=[DataRequired()])
    donation_type = SelectField('Type', choices=[
        ('one-time', 'One-Time'),
        ('recurring', 'Recurring'),
        ('in-kind', 'In-Kind'),
        ('pledge', 'Pledge')
    ])
    campaign = StringField('Campaign', validators=[Optional(), Length(max=100)])
    notes = TextAreaField('Notes', validators=[Optional()])


class CommunicationForm(FlaskForm):
    comm_type = SelectField('Type', choices=[
        ('email', 'Email'),
        ('phone', 'Phone Call'),
        ('meeting', 'Meeting'),
        ('letter', 'Letter'),
        ('event', 'Event'),
        ('other', 'Other')
    ])
    date = DateField('Date', validators=[DataRequired()])
    subject = StringField('Subject', validators=[Optional(), Length(max=200)])
    notes = TextAreaField('Notes', validators=[Optional()])


class TaskForm(FlaskForm):
    description = StringField('Description', validators=[DataRequired(), Length(max=500)])
    due_date = DateField('Due Date', validators=[Optional()])
    donor_id = SelectField('Related Donor', coerce=int, validators=[Optional()])


class RelationshipForm(FlaskForm):
    related_donor_id = SelectField('Related Donor', coerce=int, validators=[DataRequired()])
    relationship_type = SelectField('Relationship Type', choices=[
        ('spouse', 'Spouse/Partner'),
        ('family', 'Family Member'),
        ('colleague', 'Colleague'),
        ('friend', 'Friend'),
        ('board', 'Board Connection'),
        ('other', 'Other')
    ])


# =============================================================================
# AUTHENTICATION
# =============================================================================

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            flash('Welcome back!', 'success')
            return redirect(next_page if next_page else url_for('dashboard'))
        flash('Invalid email or password.', 'danger')

    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data.lower()).first():
            flash('Email already registered.', 'danger')
        else:
            user = User(
                name=form.name.data,
                email=form.email.data.lower()
            )
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()
            flash('Account created! Please log in.', 'success')
            return redirect(url_for('login'))

    return render_template('register.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


# =============================================================================
# DASHBOARD
# =============================================================================

@app.route('/')
@login_required
def dashboard():
    # Key metrics
    total_donors = Donor.query.count()
    total_donations = db.session.query(db.func.sum(Donation.amount)).scalar() or 0

    # This year's donations
    year_start = date(date.today().year, 1, 1)
    ytd_donations = db.session.query(db.func.sum(Donation.amount)).filter(
        Donation.date >= year_start
    ).scalar() or 0

    # Recent donations
    recent_donations = Donation.query.order_by(Donation.date.desc()).limit(5).all()

    # Upcoming tasks
    upcoming_tasks = Task.query.filter(
        Task.completed == False,
        Task.user_id == current_user.id
    ).order_by(Task.due_date.asc()).limit(5).all()

    # Overdue tasks count
    overdue_count = Task.query.filter(
        Task.completed == False,
        Task.due_date < date.today(),
        Task.user_id == current_user.id
    ).count()

    # Recent communications
    recent_comms = Communication.query.order_by(Communication.date.desc()).limit(5).all()

    # Donors added this month
    month_start = date.today().replace(day=1)
    new_donors_month = Donor.query.filter(Donor.created_at >= month_start).count()

    return render_template('dashboard.html',
        total_donors=total_donors,
        total_donations=total_donations,
        ytd_donations=ytd_donations,
        recent_donations=recent_donations,
        upcoming_tasks=upcoming_tasks,
        overdue_count=overdue_count,
        recent_comms=recent_comms,
        new_donors_month=new_donors_month,
        today=date.today()
    )


# =============================================================================
# DONORS
# =============================================================================

@app.route('/donors')
@login_required
def donors():
    search = request.args.get('search', '')
    page = request.args.get('page', 1, type=int)

    query = Donor.query
    if search:
        search_term = f'%{search}%'
        query = query.filter(
            db.or_(
                Donor.first_name.ilike(search_term),
                Donor.last_name.ilike(search_term),
                Donor.email.ilike(search_term)
            )
        )

    donors = query.order_by(Donor.last_name, Donor.first_name).paginate(
        page=page, per_page=20, error_out=False
    )

    return render_template('donors.html', donors=donors, search=search)


@app.route('/donors/new', methods=['GET', 'POST'])
@login_required
def new_donor():
    form = DonorForm()
    if form.validate_on_submit():
        donor = Donor(
            first_name=form.first_name.data,
            last_name=form.last_name.data,
            email=form.email.data,
            phone=form.phone.data,
            address=form.address.data,
            city=form.city.data,
            state=form.state.data,
            zip_code=form.zip_code.data,
            interests=form.interests.data,
            notes=form.notes.data
        )
        db.session.add(donor)
        db.session.commit()
        flash(f'Donor {donor.full_name} added successfully!', 'success')
        return redirect(url_for('view_donor', donor_id=donor.id))

    return render_template('donor_form.html', form=form, title='Add New Donor')


@app.route('/donors/<int:donor_id>')
@login_required
def view_donor(donor_id):
    donor = Donor.query.get_or_404(donor_id)
    donations = donor.donations.order_by(Donation.date.desc()).all()
    communications = donor.communications.order_by(Communication.date.desc()).all()
    tasks = donor.tasks.filter_by(completed=False).order_by(Task.due_date.asc()).all()

    # Get relationships
    relationships = DonorRelationship.query.filter(
        db.or_(
            DonorRelationship.donor_id == donor_id,
            DonorRelationship.related_donor_id == donor_id
        )
    ).all()

    return render_template('donor_view.html',
        donor=donor,
        donations=donations,
        communications=communications,
        tasks=tasks,
        relationships=relationships
    )


@app.route('/donors/<int:donor_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_donor(donor_id):
    donor = Donor.query.get_or_404(donor_id)
    form = DonorForm(obj=donor)

    if form.validate_on_submit():
        form.populate_obj(donor)
        db.session.commit()
        flash('Donor updated successfully!', 'success')
        return redirect(url_for('view_donor', donor_id=donor.id))

    return render_template('donor_form.html', form=form, title='Edit Donor', donor=donor)


@app.route('/donors/<int:donor_id>/delete', methods=['POST'])
@login_required
def delete_donor(donor_id):
    donor = Donor.query.get_or_404(donor_id)
    name = donor.full_name
    db.session.delete(donor)
    db.session.commit()
    flash(f'Donor {name} has been deleted.', 'info')
    return redirect(url_for('donors'))


# =============================================================================
# DONATIONS
# =============================================================================

@app.route('/donors/<int:donor_id>/donations/new', methods=['GET', 'POST'])
@login_required
def new_donation(donor_id):
    donor = Donor.query.get_or_404(donor_id)
    form = DonationForm()

    if request.method == 'GET':
        form.date.data = date.today()

    if form.validate_on_submit():
        donation = Donation(
            donor_id=donor.id,
            amount=form.amount.data,
            date=form.date.data,
            donation_type=form.donation_type.data,
            campaign=form.campaign.data,
            notes=form.notes.data
        )
        db.session.add(donation)
        db.session.commit()
        flash(f'Donation of ${donation.amount} recorded!', 'success')
        return redirect(url_for('view_donor', donor_id=donor.id))

    return render_template('donation_form.html', form=form, donor=donor)


@app.route('/donations')
@login_required
def donations():
    page = request.args.get('page', 1, type=int)
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    campaign = request.args.get('campaign')

    query = Donation.query

    if start_date:
        query = query.filter(Donation.date >= datetime.strptime(start_date, '%Y-%m-%d').date())
    if end_date:
        query = query.filter(Donation.date <= datetime.strptime(end_date, '%Y-%m-%d').date())
    if campaign:
        query = query.filter(Donation.campaign.ilike(f'%{campaign}%'))

    donations = query.order_by(Donation.date.desc()).paginate(
        page=page, per_page=20, error_out=False
    )

    # Get unique campaigns for filter dropdown
    campaigns = db.session.query(Donation.campaign).filter(
        Donation.campaign.isnot(None),
        Donation.campaign != ''
    ).distinct().all()
    campaigns = [c[0] for c in campaigns]

    return render_template('donations.html',
        donations=donations,
        campaigns=campaigns,
        filters={'start_date': start_date, 'end_date': end_date, 'campaign': campaign}
    )


@app.route('/donations/<int:donation_id>/delete', methods=['POST'])
@login_required
def delete_donation(donation_id):
    donation = Donation.query.get_or_404(donation_id)
    donor_id = donation.donor_id
    db.session.delete(donation)
    db.session.commit()
    flash('Donation deleted.', 'info')
    return redirect(url_for('view_donor', donor_id=donor_id))


# =============================================================================
# COMMUNICATIONS
# =============================================================================

@app.route('/donors/<int:donor_id>/communications/new', methods=['GET', 'POST'])
@login_required
def new_communication(donor_id):
    donor = Donor.query.get_or_404(donor_id)
    form = CommunicationForm()

    if request.method == 'GET':
        form.date.data = date.today()

    if form.validate_on_submit():
        comm = Communication(
            donor_id=donor.id,
            user_id=current_user.id,
            comm_type=form.comm_type.data,
            date=datetime.combine(form.date.data, datetime.min.time()),
            subject=form.subject.data,
            notes=form.notes.data
        )
        db.session.add(comm)
        db.session.commit()
        flash('Communication logged!', 'success')
        return redirect(url_for('view_donor', donor_id=donor.id))

    return render_template('communication_form.html', form=form, donor=donor)


@app.route('/communications')
@login_required
def communications():
    page = request.args.get('page', 1, type=int)

    comms = Communication.query.order_by(Communication.date.desc()).paginate(
        page=page, per_page=20, error_out=False
    )

    return render_template('communications.html', communications=comms)


# =============================================================================
# TASKS
# =============================================================================

@app.route('/tasks')
@login_required
def tasks():
    show_completed = request.args.get('show_completed', 'false') == 'true'

    query = Task.query.filter_by(user_id=current_user.id)

    if not show_completed:
        query = query.filter_by(completed=False)

    tasks = query.order_by(Task.completed, Task.due_date.asc()).all()

    return render_template('tasks.html', tasks=tasks, show_completed=show_completed, today=date.today())


@app.route('/tasks/new', methods=['GET', 'POST'])
@login_required
def new_task():
    form = TaskForm()

    # Populate donor choices
    donors = Donor.query.order_by(Donor.last_name, Donor.first_name).all()
    form.donor_id.choices = [(0, '-- No specific donor --')] + [(d.id, d.full_name) for d in donors]

    if form.validate_on_submit():
        task = Task(
            user_id=current_user.id,
            description=form.description.data,
            due_date=form.due_date.data,
            donor_id=form.donor_id.data if form.donor_id.data != 0 else None
        )
        db.session.add(task)
        db.session.commit()
        flash('Task created!', 'success')
        return redirect(url_for('tasks'))

    return render_template('task_form.html', form=form)


@app.route('/tasks/<int:task_id>/complete', methods=['POST'])
@login_required
def complete_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id != current_user.id:
        flash('You can only complete your own tasks.', 'danger')
        return redirect(url_for('tasks'))

    task.completed = True
    task.completed_at = datetime.utcnow()
    db.session.commit()
    flash('Task marked complete!', 'success')

    # Redirect back to referring page
    return redirect(request.referrer or url_for('tasks'))


@app.route('/tasks/<int:task_id>/delete', methods=['POST'])
@login_required
def delete_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id != current_user.id:
        flash('You can only delete your own tasks.', 'danger')
        return redirect(url_for('tasks'))

    db.session.delete(task)
    db.session.commit()
    flash('Task deleted.', 'info')
    return redirect(url_for('tasks'))


# =============================================================================
# RELATIONSHIPS
# =============================================================================

@app.route('/donors/<int:donor_id>/relationships/new', methods=['GET', 'POST'])
@login_required
def new_relationship(donor_id):
    donor = Donor.query.get_or_404(donor_id)
    form = RelationshipForm()

    # Populate donor choices (exclude current donor)
    other_donors = Donor.query.filter(Donor.id != donor_id).order_by(Donor.last_name, Donor.first_name).all()
    form.related_donor_id.choices = [(d.id, d.full_name) for d in other_donors]

    if form.validate_on_submit():
        relationship = DonorRelationship(
            donor_id=donor.id,
            related_donor_id=form.related_donor_id.data,
            relationship_type=form.relationship_type.data
        )
        db.session.add(relationship)
        db.session.commit()
        flash('Relationship added!', 'success')
        return redirect(url_for('view_donor', donor_id=donor.id))

    return render_template('relationship_form.html', form=form, donor=donor)


# =============================================================================
# REPORTS
# =============================================================================

@app.route('/reports')
@login_required
def reports():
    # Donation summary by year
    yearly_totals = db.session.query(
        db.func.strftime('%Y', Donation.date).label('year'),
        db.func.sum(Donation.amount).label('total'),
        db.func.count(Donation.id).label('count')
    ).group_by('year').order_by(db.desc('year')).all()

    # Donation summary by campaign
    campaign_totals = db.session.query(
        Donation.campaign,
        db.func.sum(Donation.amount).label('total'),
        db.func.count(Donation.id).label('count')
    ).filter(
        Donation.campaign.isnot(None),
        Donation.campaign != ''
    ).group_by(Donation.campaign).order_by(db.desc('total')).all()

    # Top donors
    top_donors = db.session.query(
        Donor,
        db.func.sum(Donation.amount).label('total')
    ).join(Donation).group_by(Donor.id).order_by(db.desc('total')).limit(10).all()

    # Donation type breakdown
    type_totals = db.session.query(
        Donation.donation_type,
        db.func.sum(Donation.amount).label('total'),
        db.func.count(Donation.id).label('count')
    ).group_by(Donation.donation_type).all()

    return render_template('reports.html',
        yearly_totals=yearly_totals,
        campaign_totals=campaign_totals,
        top_donors=top_donors,
        type_totals=type_totals
    )


# =============================================================================
# EXPORTS
# =============================================================================

@app.route('/export/donors')
@login_required
def export_donors():
    donors = Donor.query.order_by(Donor.last_name, Donor.first_name).all()

    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow(['First Name', 'Last Name', 'Email', 'Phone', 'Address', 'City', 'State', 'ZIP', 'Total Donated', 'Interests', 'Notes'])

    # Data
    for donor in donors:
        writer.writerow([
            donor.first_name,
            donor.last_name,
            donor.email or '',
            donor.phone or '',
            donor.address or '',
            donor.city or '',
            donor.state or '',
            donor.zip_code or '',
            float(donor.total_donated),
            donor.interests or '',
            donor.notes or ''
        ])

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment;filename=donors_{date.today()}.csv'}
    )


@app.route('/export/donations')
@login_required
def export_donations():
    donations = Donation.query.order_by(Donation.date.desc()).all()

    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow(['Date', 'Donor', 'Amount', 'Type', 'Campaign', 'Notes'])

    # Data
    for d in donations:
        writer.writerow([
            d.date.isoformat(),
            d.donor.full_name,
            float(d.amount),
            d.donation_type or '',
            d.campaign or '',
            d.notes or ''
        ])

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment;filename=donations_{date.today()}.csv'}
    )


# =============================================================================
# INITIALIZE DATABASE
# =============================================================================

def init_db():
    with app.app_context():
        db.create_all()
        print("Database initialized!")


# Initialize database tables on import (for gunicorn/production)
with app.app_context():
    db.create_all()


if __name__ == '__main__':
    app.run(debug=True)
