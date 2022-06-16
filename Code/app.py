from flask import *
from flask_sqlalchemy import SQLAlchemy
from passlib.hash import sha256_crypt
import os,random,re
from datetime import timedelta
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from sendgrid.helpers.mail import To

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(16)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///event_db.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config['SESSION_COOKIE_NAME'] = 'login-system'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)

#client_id="505348922138-a10mfp737qq5lmgi33opfis1ln0cka5j.apps.googleusercontent.com",
#client_secret='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',

db = SQLAlchemy(app)

#creating tables
class Organizer(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    name = db.Column(db.String(50),nullable=False)
    email = db.Column(db.String(100),nullable=False,unique=True)
    phone = db.Column(db.String(11), nullable=False, unique=True)
    password = db.Column(db.String(255),nullable=False)
    organization = db.Column(db.String(255),nullable=False)
    event_org_id=db.relationship('Event',cascade="all,delete",backref='owner')
    alert_org_id=db.relationship('Alert',cascade="all,delete",backref='owner')

    def __repr__(self):
        return '<Organizer %r>' % self.email

class Participant(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    name = db.Column(db.String(50),nullable=False)
    email = db.Column(db.String(100),nullable=False,unique=True)
    phone = db.Column(db.String(11), nullable=False, unique=True)
    password = db.Column(db.String(255),nullable=False)
    category = db.Column(db.String(50),nullable=False)
    event_id = db.Column(db.Integer,db.ForeignKey('event.id'))
    pevent_id=db.relationship('Plist',cascade="all,delete",backref='owner')

    def _repr_(self):
        return '<Participant %r>' % self.email

class Organization(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    name = db.Column(db.String(50),nullable=False)
    email = db.Column(db.String(100),nullable=False,unique=True)
    location = db.Column(db.String(100),nullable=False)

    def _repr_(self):
        return '<Organization %r>' % self.email

class Coorganizer(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    name = db.Column(db.String(50),nullable=False)
    email = db.Column(db.String(100),nullable=False,unique=True)
    phone = db.Column(db.String(11), nullable=False, unique=True)
    password = db.Column(db.String(255),nullable=False)
    organizer = db.Column(db.String(50),nullable=False)
    coorg_id=db.relationship('Event',cascade="all,delete",backref='owner1')
    
    def _repr_(self):
        return '<coorganizer %r>' % self.email

class Event(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    name = db.Column(db.String(50),nullable=False)
    description = db.Column(db.String(255),nullable=False)
    date = db.Column(db.String(50), nullable=False)
    time = db.Column(db.String(50), nullable=False)
    category = db.Column(db.String(50),nullable=False)
    coorg_mail = db.Column(db.String(80),db.ForeignKey('coorganizer.email'))
    org_id = db.Column(db.Integer,db.ForeignKey('organizer.id'))
    judge = db.Column(db.String(50),nullable=True)
    participant_id=db.relationship('Participant',cascade="all,delete",backref='participants')
    judge_event_id=db.relationship('Judge',cascade="all,delete",backref='ownersj')
    part_event_id=db.relationship('Plist',cascade="all,delete",backref='ownersjp')

    def __repr__(self):
        return '<Event %r>' % self.name

class Alert(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    attendee = db.Column(db.String(50),nullable=False)
    org_id = db.Column(db.Integer,db.ForeignKey('organizer.id'),nullable=True)

    def __repr__(self):
        return self.attendee

class Judge(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    name = db.Column(db.String(50),nullable=False)
    email = db.Column(db.String(50),nullable=False)
    password = db.Column(db.String(255),nullable=False)
    event_id = db.Column(db.Integer,db.ForeignKey('event.id'))

    def __repr__(self):
        return self.attendee

class Plist(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    part_id = db.Column(db.Integer,db.ForeignKey('participant.id'),nullable=True)
    event_id = db.Column(db.Integer,db.ForeignKey('event.id'),nullable=True)
    score=db.Column(db.Integer,nullable=True)

db.create_all()
#db.drop_all()

#home page
@app.route("/")
def home():
    return render_template('home.html')

def send_mail(recepient,mail_object,body):
    message = Mail(
    from_email=("eventxsjec@gmail.com", "EventX"),
    to_emails=recepient,
    subject=mail_object,
    html_content=body)
    sg = SendGridAPIClient(
    "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")
    sg.send(message)

#login page
@app.route("/alllog")
def alllog():
    return render_template('alllog.html')

@app.route("/admin_log")
def admin_log():
    return render_template('admin_log.html')

@app.route("/admin_dash")
def admin_dash():
    if 'admin' in session:
        organizations = Organization.query.count()
        organizers = Organizer.query.count()
        return render_template('admin_dash.html',data=[organizations,organizers])
    else:
        flash("Session Expired", "error")
        return redirect(url_for('admin_log'))

#main admin login
@app.route("/adminlog",methods=['POST'])
def mainadmin_log():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        if email == 'mainadmin@gmail.com' and password == 'event123':
            session['admin'] = True
            session['admin_name'] = email
            flash('Login Successfull','success')
            return redirect(url_for('admin_dash'))
        else:
            flash('Invalid Credentials','error')
            return redirect(url_for('admin_log'))
    else:
        session.clear()
        flash('Unauthorized access','error')
        return redirect(url_for('home'))

@app.route("/participantreg")
def participantreg():
    return render_template('participantreg.html')

#participant registeration
@app.route("/participant_register",methods=["POST"])
def participant_register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        category = request.form['category']
        password = request.form['password']
        email_check = Participant.query.filter_by(email=email).first()
        if not email_check:
            phone_check = Participant.query.filter_by(phone=phone).first()
            if not phone_check:
                flag = 0
                while True:  
                    if (len(password)<8):
                        flag = -1
                        break
                    elif not re.search("[a-z]", password):
                        flag = -1
                        break
                    elif not re.search("[A-Z]", password):
                        flag = -1
                        break
                    elif not re.search("[0-9]", password):
                        flag = -1
                        break
                    elif not re.search("[_@$]", password):
                        flag = -1
                        break
                    elif re.search("\\s", password):
                        flag = -1
                        break
                    else:
                        flag = 0
                        break
                if flag ==-1:
                    flash("Not a Valid Password","error")
                    return redirect(url_for("participantreg"))
                hash_pass = sha256_crypt.hash(password)
                participant = Participant(name=name,email=email,phone=phone,category=category,password=hash_pass)
                db.session.add(participant)
                db.session.commit()
                #send_mail(email,"Registration Successfull","Thank you for registering on our website.Hope you have a good experience")
                flash('Registeration successfully','success')
                return redirect(url_for('participantlog'))
            else:
                flash("Phone Number already registered","error")
                return redirect(url_for('participantreg'))
        else:
            flash("Email ID already registered","error")
            return redirect(url_for('participantreg'))
    else:
        session.clear()
        flash('Unauthorized access','error')
        return redirect(url_for('home'))


@app.route("/participantlog")
def participantlog():
    return render_template('participant_log.html')

#participant login
@app.route("/participant_login",methods=['POST'])
def participant_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        response = Participant.query.filter_by(email=email).first()
        if not response:
            flash("Email ID not registered",'error')
            return redirect(url_for("participantlog"))
        else:
            checkpass = sha256_crypt.verify(password,response.password)
            if email == response.email and checkpass == True:
                session['participant'] = True
                session['participant_id'] = response.id
                session['participant_name'] = response.name
                session['participant_email'] = response.email
                session['participant_phone'] = response.phone
                session['participant_category'] = response.category
                flash('You were successfully logged in',"success")
                return redirect(url_for("participantdash"))
            else:
                flash('Invalid Credentials',"error")
                return redirect(url_for("participantlog"))
    else:
        session.clear()
        flash('Unauthorized access','error')
        return redirect(url_for('home'))

@app.route("/participantdash")
def participantdash():
    if 'participant' in session:
        return render_template('participant_dash.html')
    else:
        flash("Session Expired", "error")
        return redirect(url_for("participantlog"))

@app.route("/participant_forpass")
def participant_forpass():
    return render_template('participant_forpass.html')

#participant forgot password
@app.route("/participant_send_otp",methods=['POST'])
def participant_send_otp():
    if request.method == 'POST':
        email = request.form['email']
        email_check = Participant.query.filter_by(email=email).first()
        if email_check:
            session['participant'] = True
            session['email'] = email_check.email
            otp = random.randint(000000,999999)
            session['otp'] = otp
            #send_mail(email,'OTP for Password change',"Dear participant, your verification code is: " + str(otp))
            flash("OTP sent","success")
            return redirect(url_for("participant_otp"))
        else:
            flash("Email ID not registered. Please check your email id or create a new account","error")
            return redirect(url_for('participantlog'))
    else:
        session.clear()
        flash('Unauthorized access','error')
        return redirect(url_for('home'))

@app.route("/participant_otp")
def participant_otp():
    return render_template('participant_otp.html')

#participant otp verification for forgot password
@app.route('/participant_verify',methods=['POST'])
def participant_verify():
    if request.method == "POST":
        if 'participant' in session:
            participant_otp = request.form['participant_otp']
            if session['otp'] == int(participant_otp):
                return redirect(url_for("participant_forpass_form"))
            else:
                flash("Wrong OTP. Please try again","error")
                return redirect(url_for("participant_otp"))
        else:
            flash("Session Expired","error")
            return redirect(url_for('participantlog'))
    else:
        session.clear()
        flash('Unauthorized access','error')
        return redirect(url_for('home'))

@app.route("/participant_forpass_form")
def participant_forpass_form():
    return render_template('participant_forpass_form.html')

#participant change password after otp verification
@app.route('/change_participant_pass',methods=['POST'])
def change_participant_pass():
    if request.method == "POST":
        if 'participant' in session:
            pass1 = request.form['pass1']
            flag = 0
            while True:  
                if (len(pass1)<8):
                    flag = -1
                    break
                elif not re.search("[a-z]", pass1):
                    flag = -1
                    break
                elif not re.search("[A-Z]", pass1):
                    flag = -1
                    break
                elif not re.search("[0-9]", pass1):
                    flag = -1
                    break
                elif not re.search("[_@$]", pass1):
                    flag = -1
                    break
                elif re.search("\\s", pass1):
                    flag = -1
                    break
                else:
                    flag = 0
                    break
            if flag ==-1:
                flash("Not a Valid Password","error")
                return redirect(url_for("participant_forpass_form"))
            pass2 = request.form['pass2']
            if pass1 == pass2:
                hash_pass = sha256_crypt.hash(pass1)
                data = Participant.query.filter_by(email=session['email']).first()
                data.password = hash_pass
                db.session.commit()
                session.pop('participant',None)
                session.pop('email',None)
                flash("Password changed successfully","success")
                return redirect(url_for("participantlog"))
            else:
                flash("Passwords dont match",'error')
                return redirect(url_for('participant_forpass_form'))
        else:
            flash("Session Expired","error")
            return redirect(url_for('participantlog'))
    else:
        session.clear()
        flash('Unauthorized access','error')
        return redirect(url_for('home'))

@app.route("/participant_profile")
def participant_profile():
    return render_template('participant_profile.html')

@app.route("/participant_profile_update")
def participant_profile_update():
    if 'participant' in session:
        get_participant_data = Participant.query.filter_by(id=session['participant_id']).first()
        return render_template('participant_profupdate.html',data=get_participant_data)
    else:
        flash("Session Expired", "error")
        return redirect(url_for("participantlog"))

#participant profile update
@app.route("/update_participant_profile/<int:id>",methods=['POST'])
def update_participant_profile(id):
    if 'participant' in session:
        if request.method == 'POST':
            name = request.form['name']
            email = request.form['email']
            phno = request.form['phno']
            category = request.form['category']
            data = Participant.query.filter_by(id=id).first()
            email_check = Participant.query.filter_by(email=email).first()
            if email_check:
                if(email_check.id != id):
                    flash("Email ID is already used by someone else","error")
                    data = Participant.query.filter_by(id=id).first()
                    return render_template('participant_profupdate.html',data=data)
                elif(email_check.id == id):
                    data.email = email
                    data.name = name
                    phno_check = Participant.query.filter_by(phone=phno).first()
                    if phno_check:
                        if(phno_check.id != id):
                            flash("Phone number is already used by someone else","error")
                            data = Participant.query.filter_by(id=id).first()
                            return render_template('participant_profupdate.html',data=data)
                        elif(phno_check.id == id):
                            data.phone = phno
                            data.category = category
                            db.session.commit()
                            session.clear()
                            flash("Participant details updated successfully.Login again to see changes","success")
                            return redirect(url_for("participantlog"))
                    else:
                        data.phone = phno
                        data.category = category
                        db.session.commit()
                        session.clear()
                        flash("Participant details updated successfully.Login again to see changes","success")
                        return redirect(url_for("participantlog"))
            else:
                data.email = email
                data.name = name
                phno_check = Participant.query.filter_by(phone=phno).first()
                if phno_check:
                    if(phno_check.id != id):
                        flash("Phone number is already used by someone else","error")
                        data = Participant.query.filter_by(id=id).first()
                        return render_template('participant_profupdate.html',data=data)
                    elif(phno_check.id == id):
                        data.phone = phno
                        data.category = category
                        db.session.commit()
                        session.clear()
                        flash("Participant details updated successfully.Login again to see changes","success")
                        return redirect(url_for("participantlog"))
                else:
                    data.phone = phno
                    data.category = category
                    db.session.commit()
                    session.clear()
                    flash("Participant details updated successfully.Login again to see changes","success")
                    return redirect(url_for("participantlog"))
        else:
            session.clear()
            flash('Unauthorized access','error')
            return redirect(url_for('home'))
    else:
        flash("Session Expired","error")
        return redirect(url_for('participantlog'))

@app.route("/change_pass_participant")
def change_pass_participant():
    if 'participant' in session:
        get_participant_data = Participant.query.filter_by(id=session['participant_id']).first()
        return render_template('change_pass_participant.html',data=get_participant_data) 
    else:
        flash("Session Expired", "error")
        return redirect(url_for("participantlog"))

#participant change password after login            
@app.route('/participant_change_pass',methods=['POST'])
def participant_change_pass():
    if request.method == 'POST':
        if 'participant' in session:
            email = request.form['email']
            pass1 = request.form['pass1']
            flag = 0
            while True:  
                if (len(pass1)<8):
                    flag = -1
                    break
                elif not re.search("[a-z]", pass1):
                    flag = -1
                    break
                elif not re.search("[A-Z]", pass1):
                    flag = -1
                    break
                elif not re.search("[0-9]", pass1):
                    flag = -1
                    break
                elif not re.search("[_@$]", pass1):
                    flag = -1
                    break
                elif re.search("\\s", pass1):
                    flag = -1
                    break
                else:
                    flag = 0
                    break
            if flag ==-1:
                flash("Not a Valid Password","error")
                return redirect(url_for("changepass_participant"))
            pass2 = request.form['pass2']
            if pass1 == pass2:
                email_check = Participant.query.filter_by(email=email).first()
                if email_check:
                    hash_pass = sha256_crypt.hash(pass1)
                    email_check.password = hash_pass
                    db.session.commit()
                    flash("Password changed successfully","success")
                    return redirect(url_for("participantdash"))
                else:
                    flash("Check your email and try again","error")
                    return redirect(url_for("changepass_participant"))
            else:
                flash("Passwords dont match",'error')
                return redirect(url_for('changepass_participant'))
        else:
            flash("Session Expired","error")
            return redirect(url_for('participantlog'))
    else:
        session.clear()
        flash('Unauthorized access','error')
        return redirect(url_for('home'))

@app.route("/organization")
def organization():
    if 'admin' in session:
        return render_template('add_organization.html')
    else:
        flash("Session Expired","error")
        return redirect(url_for('admin_log'))

#adding organization
@app.route("/add_organization",methods=["POST"])
def add_organization():
    if request.method == 'POST':
        if 'admin' in session:
            name = request.form['name']
            email = request.form['email']     
            location = request.form['location']
            email_check = Organization.query.filter_by(email=email).first()
            if not email_check:
                organization = Organization(name=name,email=email,location=location)
                db.session.add(organization)
                db.session.commit()
                flash('Organization added successfully','success')
                return redirect(url_for('admin_dash'))
            else:
                flash("Email ID already used","error")
                return redirect(url_for('organization'))
        else:
            flash("Session Expired","error")
            return redirect(url_for('admin_log'))
    else:
        session.clear()
        flash('Unauthorized access','error')
        return redirect(url_for('home'))

@app.route("/organizer")
def organizer():
    if 'admin' in session:
        organizations = Organization.query.count()
        if not organizations:
            flash("Add atleast one organization","error")
            return redirect(url_for('admin_dash'))
        else:
            get_organization_data = Organization.query.all()
            return render_template('add_organizer.html',data=get_organization_data)
    else:
        flash("Session Expired","error")
        return redirect(url_for('admin_log'))

#adding organizer
@app.route("/add_organizer",methods=["POST"])
def add_organizer():
    if request.method == 'POST':
        if 'admin' in session:
            name = request.form['name']
            email = request.form['email']     
            phone = request.form['phone']
            organization = request.form['organization']
            email_check = Organizer.query.filter_by(email=email).first()
            if not email_check:
                phone_check = Organizer.query.filter_by(phone=phone).first()
                if not phone_check:
                    hash_pass = sha256_crypt.hash(email)
                    organizer = Organizer(name=name,email=email,phone=phone,password=hash_pass,organization=organization)
                    db.session.add(organizer)
                    db.session.commit()
                    #send_mail(email,"You are a Organizer!","You have been successfully added as a ORGANIZER under the organization "+str(organization).upper()+". Please use your email as your password on your first login and change it by clicking the change password option")
                    flash('Organizer added successfully','success')
                    return redirect(url_for('admin_dash'))
                else:
                    flash("Phone Number already registered","error")
                    return redirect(url_for('organizer'))
            else:
                flash("Email ID already used","error")
                return redirect(url_for('organizer'))
        else:
            flash("Session Expired","error")
            return redirect(url_for('admin_log'))
    else:
        session.clear()
        flash('Unauthorized access','error')
        return redirect(url_for('home'))

@app.route("/organizer_log",methods=['GET','POST'])
def organizer_log():
    return render_template('organizer_log.html')

#organizer login
@app.route("/organizerlog",methods=['POST'])
def organizerlog():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        response = Organizer.query.filter_by(email=email).first()
        if not response:
            flash("Email ID not registered",'error')
            return redirect(url_for("organizer_log"))   
        else:
            checkpass = sha256_crypt.verify(password,response.password)
            if email == response.email and checkpass == True:
                session['organizer'] = True
                session['organizer_id'] = response.id
                session['organizer_name'] = response.name
                session['organizer_email'] = response.email
                session['organizer_phone'] = response.phone
                session['organizer_organization'] = response.organization
                flash('You were successfully logged in',"success")
                return redirect(url_for("organizerdash"))
            else:
                flash('Invalid Credentials',"error")
                return redirect(url_for("organizer_log"))
    else:
        session.clear()
        flash('Unauthorized access','error')
        return redirect(url_for('home'))

@app.route("/organizerdash")
def organizerdash():
    if 'organizer' in session:
        co_organizers = Coorganizer.query.count()
        events = Event.query.count()
        return render_template('organizer_dash.html',data=[co_organizers,events])
    else:
        flash("Session Expired", "error")
        return redirect(url_for("organizer_log"))

@app.route("/organizer_profile")
def organizer_profile():
    if 'organizer' in session:
        return render_template('organizer_profile.html')
    else:
        flash("Session Expired", "error")
        return redirect(url_for("organizer_log"))

@app.route("/organizer_profile_update")
def organizer_profile_update():
    if 'organizer' in session:
        get_organizer_data = Organizer.query.filter_by(id=session['organizer_id']).first()
        return render_template('organizer_profupdate.html',data=get_organizer_data)
    else:
        flash("Session Expired", "error")
        return redirect(url_for("organizer_log"))

#organizer profile update
@app.route("/update_organizer_profile/<int:id>",methods=['POST'])
def update_organizer_profile(id):
    if 'organizer' in session:
        if request.method == 'POST':
            name = request.form['name']
            phno = request.form['phno']
            data = Organizer.query.filter_by(id=id).first()
            phno_check = Organizer.query.filter_by(phone=phno).first()
            if phno_check:
                if(phno_check.id != id):
                    flash("Phone number is already used by someone else","error")
                    data = Organizer.query.filter_by(id=id).first()
                    return render_template('organizer_profupdate.html',data=data)
                elif(phno_check.id == id):
                    data.phone = phno
                    data.name = name
                    db.session.commit()
                    session.clear()
                    flash("Organizer details updated successfully.Login again to see changes","success")
                    return redirect(url_for("organizer_log"))
            else:
                data.phone = phno
                data.name = name
                db.session.commit()
                session.clear()
                flash("Organizer details updated successfully.Login again to see changes","success")
                return redirect(url_for("organizer_log"))
        else:
            session.clear()
            flash('Unauthorized access','error')
            return redirect(url_for('home'))
    else:
        flash("Session Expired","error")
        return redirect(url_for('organizer_log'))

@app.route("/change_pass_organizer")
def change_pass_organizer():
    if 'organizer' in session:
        get_organizer_data = Organizer.query.filter_by(id=session['organizer_id']).first()
        return render_template('change_pass_organizer.html',data=get_organizer_data) 
    else:
        flash("Session Expired", "error")
        return redirect(url_for("organizer_log"))

#organizer change password after login            
@app.route('/organizer_change_pass/<string:email>',methods=['POST'])
def organizer_change_pass(email):
    if request.method == 'POST':
        if 'organizer' in session:
            data = Organizer.query.filter_by(email=email).first()
            pass1 = request.form['pass1']
            flag = 0
            while True:  
                if (len(pass1)<8):
                    flag = -1
                    break
                elif not re.search("[a-z]", pass1):
                    flag = -1
                    break
                elif not re.search("[A-Z]", pass1):
                    flag = -1
                    break
                elif not re.search("[0-9]", pass1):
                    flag = -1
                    break
                elif not re.search("[_@$]", pass1):
                    flag = -1
                    break
                elif re.search("\\s", pass1):
                    flag = -1
                    break
                else:
                    flag = 0
                    break
            if flag ==-1:
                flash("Not a Valid Password","error")
                return redirect(url_for("change_pass_organizer"))
            pass2 = request.form['pass2']
            if pass1 == pass2:
                hash_pass = sha256_crypt.hash(pass1)
                data.password = hash_pass
                db.session.commit()
                flash("Password changed successfully","success")
                return redirect(url_for("organizerdash"))
            else:
                flash("Passwords dont match",'error')
                return redirect(url_for('change_pass_organizer'))
        else:
            flash("Session Expired","error")
            return redirect(url_for('organizer_log'))
    else:
        session.clear()
        flash('Unauthorized access','error')
        return redirect(url_for('home'))

@app.route("/organizer_forpass")
def organizer_forpass():
    return render_template('organizer_forpass.html')

#organizer forgot password
@app.route("/organizer_send_otp",methods=['POST'])
def organizer_send_otp():
    if request.method == 'POST':
        email = request.form['email']
        email_check = Organizer.query.filter_by(email=email).first()
        if email_check:
            session['organizer'] = True
            session['email'] = email_check.email
            otp = random.randint(000000,999999)
            session['otp'] = otp
            #send_mail(email,'OTP for Password change',"Dear organizer, your verification code is: " + str(otp))
            flash("OTP sent","success")
            return redirect(url_for("organizer_otp"))
        else:
            flash("Email ID not registered. Please check your email id or ask admin to create a new account","error")
            return redirect(url_for('organizer_log'))
    else:
        session.clear()
        flash('Unauthorized access','error')
        return redirect(url_for('home'))

@app.route("/organizer_otp")
def organizer_otp():
    return render_template('organizer_otp.html')

#organizer otp verification for forgot password
@app.route('/organizer_verify',methods=['POST'])
def organizer_verify():
    if request.method == "POST":
        if 'organizer' in session:
            organizer_otp = request.form['organizer_otp']
            if session['otp'] == int(organizer_otp):
                return redirect(url_for("organizer_forpass_form"))
            else:
                flash("Wrong OTP. Please try again","error")
                return redirect(url_for("organizer_otp"))
        else:
            flash("Session Expired","error")
            return redirect(url_for('organizer_log'))
    else:
        session.clear()
        flash('Unauthorized access','error')
        return redirect(url_for('home'))

@app.route("/organizer_forpass_form")
def organizer_forpass_form():
    return render_template('organizer_forpass_form.html')

#organizer change password after otp verification
@app.route('/change_organizer_pass',methods=['POST'])
def change_organizer_pass():
    if request.method == "POST":
        if 'organizer' in session:
            pass1 = request.form['pass1']
            flag = 0
            while True:  
                if (len(pass1)<8):
                    flag = -1
                    break
                elif not re.search("[a-z]", pass1):
                    flag = -1
                    break
                elif not re.search("[A-Z]", pass1):
                    flag = -1
                    break
                elif not re.search("[0-9]", pass1):
                    flag = -1
                    break
                elif not re.search("[_@$]", pass1):
                    flag = -1
                    break
                elif re.search("\\s", pass1):
                    flag = -1
                    break
                else:
                    flag = 0
                    break
            if flag ==-1:
                flash("Not a Valid Password","error")
                return redirect(url_for("organizer_forpass_form"))
            pass2 = request.form['pass2']
            if pass1 == pass2:
                hash_pass = sha256_crypt.hash(pass1)
                data = Organizer.query.filter_by(email=session['email']).first()
                data.password = hash_pass
                db.session.commit()
                session.pop('organizer',None)
                session.pop('email',None)
                flash("Password changed successfully","success")
                return redirect(url_for("organizer_log"))
            else:
                flash("Passwords dont match",'error')
                return redirect(url_for('organizer_forpass_form'))
        else:
            flash("Session Expired","error")
            return redirect(url_for('organizer_log'))
    else:
        session.clear()
        flash('Unauthorized access','error')
        return redirect(url_for('home'))

@app.route("/add_event")
def add_event():
    if 'organizer' in session:
        coOrganizer = Coorganizer.query.count()
        if not coOrganizer:
            flash("Add Co-organizer to be assigned first","error")
            return redirect(url_for('organizerdash'))
        else:
            get_coOrganizer_data = Coorganizer.query.all()
            return render_template('add_event.html',data=get_coOrganizer_data)
    else:
        flash("Session Expired","error")
        return redirect(url_for('organizer_log'))

@app.route("/addevent",methods=["POST"])
def addevent():
    if request.method == 'POST':
        if 'organizer' in session:
            org_id = session['organizer_id']
            name = request.form['name']
            description = request.form['description']     
            date = request.form['date']
            time = request.form['time']
            category = request.form['category']
            coOrganizer = request.form['co-organizer']
            data = Coorganizer.query.filter_by(name=coOrganizer).first()
            print(data,data.email)
            email = data.email
            name_check = Event.query.filter_by(name=name).first()
            if not name_check:
                event = Event(name=name,description=description,date=date,time=time,category=category,coorg_mail=email,org_id=org_id)
                db.session.add(event)
                db.session.commit()
                send_mail(email,"Event Alloted!","You have been assigned to co-ordinate the "+str(name).upper()+" event. Please login into your dashboard and check for the event details.")
                flash('Event added successfully','success')
                return redirect(url_for('organizerdash'))
            else:
                flash("Name already used","error")
                return redirect(url_for('add_event'))
        else:
            flash("Session Expired","error")
            return redirect(url_for('organizer_log'))
    else:
        session.clear()
        flash('Unauthorized access','error')
        return redirect(url_for('home'))

@app.route("/view_event")
def view_event():
    if 'organizer' in session:
        events = Event.query.all()
        return render_template('view_event.html',data=events)
    else:
        flash("Session Expired","error")
        return redirect(url_for('organizer_log'))

@app.route("/edit_event/<int:id>",methods=['GET','POST'])
def edit_event(id):
    if 'organizer' in session:
        event = Event.query.filter_by(id=id).first()
        get_coOrganizer_data = Coorganizer.query.all()
        if session['organizer_name'] == str(event.organizer):
            return render_template('edit_event.html',data=event,coorg = get_coOrganizer_data)
        else:
            flash("You can only edit the events added by you","error")
            return redirect(url_for('view_event'))
    else:
        flash("Session Expired","error")
        return redirect(url_for('organizer_log'))

@app.route("/editevent/<int:id>",methods=["POST"])
def editevent(id):
    if request.method == 'POST':
        if 'organizer' in session:
            event = Event.query.filter_by(id=id).first()
            name = request.form['name']
            description = request.form['description']     
            date = request.form['date']
            time = request.form['time']
            category = request.form['category']
            coOrganizer = request.form['co-organizer']
            name_check = Event.query.filter_by(name=name).first()
            if not name_check:
                event.name = name
                event.description = description
                event.date = date
                event.time = time
                event.category = category
                if event.coOrganizer != coOrganizer:
                    event.coOrganizer = coOrganizer
                    db.session.commit()
                    data = Coorganizer.query.filter_by(name=coOrganizer).first()
                    email = data.email
                    send_mail(email,"Event Alloted!","You have been assigned to co-ordinate the "+str(name).upper()+" event. Please login into your dashboard and check for the event details.")
                    flash('Event updated successfully','success')
                    return redirect(url_for('organizerdash'))
                else:
                    db.session.commit()
                    flash('Event updated successfully','success')
                    return redirect(url_for('organizerdash'))
            elif name_check.id == id:
                event.description = description
                event.date = date
                event.time = time
                event.category = category
                if event.coOrganizer != coOrganizer:
                    event.coOrganizer = coOrganizer
                    db.session.commit()
                    data = Coorganizer.query.filter_by(name=coOrganizer).first()
                    email = data.email
                    send_mail(email,"Event Alloted!","You have been assigned to co-ordinate the "+str(name).upper()+" event. Please login into your dashboard and check for the event details.")
                    flash('Event updated successfully','success')
                    return redirect(url_for('organizerdash'))
                else:
                    db.session.commit()
                    flash('Event updated successfully','success')
                    return redirect(url_for('organizerdash'))
            else: 
                flash("Name already used","error")
                return redirect(url_for('view_event'))
        else:
            flash("Session Expired","error")
            return redirect(url_for('organizer_log'))
    else:
        session.clear()
        flash('Unauthorized access','error')
        return redirect(url_for('home'))
    
@app.route("/del_event/<int:id>")
def del_event(id):
    if 'organizer' in session:
        event = Event.query.filter_by(id=id).first()
        db.session.delete(event)
        db.session.commit()
        flash("Event deleted successfully","success")
        return redirect(url_for('view_event'))
    else:
        flash("Session Expired","error")
        return redirect(url_for('organizer_log'))

@app.route("/add_coOrganizer")
def add_coOrganizer():
    if 'organizer' in session:
        return render_template('add_coOrganizer.html')
    else:
        flash("Session Expired","error")
        return redirect(url_for('organizer_log'))

#adding organizer
@app.route("/addcoOrganizer",methods=["POST"])
def addcoOrganizer():
    if request.method == 'POST':
        if 'organizer' in session:
            organization = session['organizer_organization']
            organizer = session['organizer_name']
            name = request.form['name']
            email = request.form['email']     
            phone = request.form['phone']
            email_check = Coorganizer.query.filter_by(email=email).first()
            if not email_check:
                phone_check = Coorganizer.query.filter_by(phone=phone).first()
                if not phone_check:
                    hash_pass = sha256_crypt.hash(email)
                    coOrganizer = Coorganizer(name=name,email=email,phone=phone,password=hash_pass,organizer=organizer)
                    db.session.add(coOrganizer)
                    db.session.commit()
                    send_mail(email,"You are a Co-Organizer!","You have been successfully added as a CO-ORGANIZER under the organization "+str(organization).upper()+". Please use your email as your password on your first login and change it by clicking the change password option")
                    flash('Co-Organizer added successfully','success')
                    return redirect(url_for('organizerdash'))
                else:
                    flash("Phone Number already registered","error")
                    return redirect(url_for('add_coOrganizer'))
            else:
                flash("Email ID already used","error")
                return redirect(url_for('add_coOrganizer'))
        else:
            flash("Session Expired","error")
            return redirect(url_for('organizer_log'))
    else:
        session.clear()
        flash('Unauthorized access','error')
        return redirect(url_for('home'))

@app.route("/view_coOrganizer")
def view_coOrganizer():
    if 'organizer' in session:
        coorgs = Coorganizer.query.all()
        return render_template('view_coOrganizer.html',data=coorgs)
    else:
        flash("Session Expired","error")
        return redirect(url_for('organizer_log'))

@app.route("/del_coOrganizer/<int:id>")
def del_coOrganizer(id):
    if 'organizer' in session:
        coOrganizer = Coorganizer.query.filter_by(id=id).first()
        db.session.delete(coOrganizer)
        db.session.commit()
        flash("Co-Organizer deleted successfully","success")
        return redirect(url_for('view_coOrganizer'))
    else:
        flash("Session Expired","error")
        return redirect(url_for('organizer_log'))

@app.route("/send_alert")
def send_alert():
    if 'organizer' in session:
        alerts = Alert.query.all()
        return render_template('send_alert.html',data=alerts)
    else:
        flash("Session Expired","error")
        return redirect(url_for('organizer_log'))

@app.route("/sendalert",methods=["POST"])
def sendalert():
    if request.method == 'POST':
        if 'organizer' in session:
            subject = request.form['subject']
            messages = request.form['message']
            attendees = Alert.query.all()
            if attendees:
                recp=[]
                for i in attendees:
                    recp.append(str(i))
                    message = Mail(
                from_email=("eventxsjec@gmail.com", "EventX"),
                    to_emails=recp,
                    subject=subject,
                    html_content=messages)
                    sg = SendGridAPIClient(
                    "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")
                    sg.send(message)
                flash("Alert message broadcasted","success")
                return redirect(url_for('send_alert'))
            else:
                flash("Add atleast one attendee","error")
                return redirect(url_for('send_alert'))
        else:
            flash("Session Expired","error")
            return redirect(url_for('organizer_log'))
    else:
        session.clear()
        flash('Unauthorized access','error')
        return redirect(url_for('home'))

@app.route("/add_attendee/<string:email>")
def add_attendee(email):
    if 'organizer' in session:
        data = Alert.query.filter_by(attendee=email).first()
        if not data:
            alert=Alert(attendee=email,organizer=session['organizer_name'])
            db.session.add(alert)
            db.session.commit()
            flash('Attendee added successfully','success')
            return redirect(url_for('send_alert'))
        else:
            flash("Attendee already added","error")
            return redirect(url_for('send_alert'))
    else:
        flash("Session Expired","error")
        return redirect(url_for('organizer_log'))

@app.route("/del_attendee/<int:id>")
def del_attendee(id):
    if 'organizer' in session:
        attendee = Alert.query.filter_by(id=id).first()
        db.session.delete(attendee)
        db.session.commit()
        flash("Attendee removed successfully","success")
        return redirect(url_for('send_alert'))
    else:
        flash("Session Expired","error")
        return redirect(url_for('organizer_log'))

@app.route("/coOrganizer_log",methods=['GET','POST'])
def coOrganizer_log():
    return render_template('coOrganizer_log.html')

#co-organizer login
@app.route("/coOrganizerlog",methods=['POST'])
def coOrganizerlog():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        response = Coorganizer.query.filter_by(email=email).first()
        if not response:
            flash("Email ID not registered",'error')
            return redirect(url_for("coOrganizer_log"))   
        else:
            checkpass = sha256_crypt.verify(password,response.password)
            if email == response.email and checkpass == True:
                session['coorganizer'] = True
                session['coorganizer_id'] = response.id
                session['coorganizer_name'] = response.name
                session['coorganizer_email'] = response.email
                session['coorganizer_phone'] = response.phone
                session['coorganizer_organizer'] = response.organizer
                flash('You were successfully logged in',"success")
                return redirect(url_for("coOrganizerdash"))
            else:
                flash('Invalid Credentials',"error")
                return redirect(url_for("coOrganizer_log"))
    else:
        session.clear()
        flash('Unauthorized access','error')
        return redirect(url_for('home'))

@app.route("/coOrganizerdash")
def coOrganizerdash():
    if 'coorganizer' in session:
        """ co_organizers = Coorganizer.query.count()
        events = Event.query.count() """
        return render_template('coOrganizer_dash.html')
    else:
        flash("Session Expired", "error")
        return redirect(url_for("coOrganizer_log"))


@app.route("/coOrganizer_profile")
def coOrganizer_profile():
    if 'coorganizer' in session:
        return render_template('coOrganizer_profile.html')
    else:
        flash("Session Expired", "error")
        return redirect(url_for("coOrganizer_log"))

@app.route("/coOrganizer_profile_update")
def coOrganizer_profile_update():
    if 'coorganizer' in session:
        get_coOrganizer_data = Coorganizer.query.filter_by(id=session['coOrganizer_id']).first()
        return render_template('coOrganizer_profupdate.html',data=get_coOrganizer_data)
    else:
        flash("Session Expired", "error")
        return redirect(url_for("coOrganizer_log"))

#coOrganizer profile update
@app.route("/update_coOrganizer_profile/<int:id>",methods=['POST'])
def update_coOrganizer_profile(id):
    if 'coorganizer' in session:
        if request.method == 'POST':
            name = request.form['name']
            phno = request.form['phno']
            data = Coorganizer.query.filter_by(id=id).first()
            phno_check = Coorganizer.query.filter_by(phone=phno).first()
            if phno_check:
                if(phno_check.id != id):
                    flash("Phone number is already used by someone else","error")
                    data = Coorganizer.query.filter_by(id=id).first()
                    return render_template('coOrganizer_profupdate.html',data=data)
                elif(phno_check.id == id):
                    data.phone = phno
                    data.name = name
                    db.session.commit()
                    session.clear()
                    flash("Co-Organizer details updated successfully.Login again to see changes","success")
                    return redirect(url_for("coOrganizer_log"))
            else:
                data.phone = phno
                data.name = name
                db.session.commit()
                session.clear()
                flash("Co-Organizer details updated successfully.Login again to see changes","success")
                return redirect(url_for("coOrganizer_log"))
        else:
            session.clear()
            flash('Unauthorized access','error')
            return redirect(url_for('home'))
    else:
        flash("Session Expired","error")
        return redirect(url_for('coOrganizer_log'))

@app.route("/change_pass_coOrganizer")
def change_pass_coOrganizer():
    if 'coorganizer' in session:
        get_coOrganizer_data = Coorganizer.query.filter_by(id=session['coorganizer_id']).first()
        return render_template('change_pass_coOrganizer.html',data=get_coOrganizer_data) 
    else:
        flash("Session Expired", "error")
        return redirect(url_for("coOrganizer_log"))

#coOrganizer change password after login            
@app.route('/coOrganizer_change_pass/<string:email>',methods=['POST'])
def coOrganizer_change_pass(email):
    if request.method == 'POST':
        if 'coorganizer' in session:
            data = Coorganizer.query.filter_by(email=session['coorganizer_email']).first()
            pass1 = request.form['pass1']
            flag = 0
            while True:  
                if (len(pass1)<8):
                    flag = -1
                    break
                elif not re.search("[a-z]", pass1):
                    flag = -1
                    break
                elif not re.search("[A-Z]", pass1):
                    flag = -1
                    break
                elif not re.search("[0-9]", pass1):
                    flag = -1
                    break
                elif not re.search("[_@$]", pass1):
                    flag = -1
                    break
                elif re.search("\\s", pass1):
                    flag = -1
                    break
                else:
                    flag = 0
                    break
            if flag ==-1:
                flash("Not a Valid Password","error")
                return redirect(url_for("change_pass_coOrganizer"))
            pass2 = request.form['pass2']
            if pass1 == pass2:
                hash_pass = sha256_crypt.hash(pass1)
                data.password = hash_pass
                db.session.commit()
                flash("Password changed successfully","success")
                return redirect(url_for("coOrganizerdash"))
            else:
                flash("Passwords dont match",'error')
                return redirect(url_for('change_pass_coOrganizer'))
        else:
            flash("Session Expired","error")
            return redirect(url_for('coOrganizer_log'))
    else:
        session.clear()
        flash('Unauthorized access','error')
        return redirect(url_for('home'))

@app.route("/coOrganizer_forpass")
def coOrganizer_forpass():
    return render_template('coOrganizer_forpass.html')

#coOrganizer forgot password
@app.route("/coOrganizer_send_otp",methods=['POST'])
def coOrganizer_send_otp():
    if request.method == 'POST':
        email = request.form['email']
        email_check = Coorganizer.query.filter_by(email=email).first()
        if email_check:
            session['coorganizer'] = True
            session['email'] = email_check.email
            otp = random.randint(000000,999999)
            session['otp'] = otp
            send_mail(email,'OTP for Password change',"Dear Co-Organizer, your verification code is: " + str(otp))
            flash("OTP sent","success")
            return redirect(url_for("coOrganizer_otp"))
        else:
            flash("Email ID not registered. Please check your email id or ask organizer to create a new account","error")
            return redirect(url_for('coOrganizer_log'))
    else:
        session.clear()
        flash('Unauthorized access','error')
        return redirect(url_for('home'))

@app.route("/coOrganizer_otp")
def coOrganizer_otp():
    return render_template('coOrganizer_otp.html')

#Co-Organizer otp verification for forgot password
@app.route('/coOrganizer_verify',methods=['POST'])
def coOrganizer_verify():
    if request.method == "POST":
        if 'coorganizer' in session:
            coOrganizer_otp = request.form['coorganizer_otp']
            if session['otp'] == int(coOrganizer_otp):
                return redirect(url_for("coOrganizer_forpass_form"))
            else:
                flash("Wrong OTP. Please try again","error")
                return redirect(url_for("coOrganizer_otp"))
        else:
            flash("Session Expired","error")
            return redirect(url_for('coOrganizer_log'))
    else:
        session.clear()
        flash('Unauthorized access','error')
        return redirect(url_for('home'))

@app.route("/coOrganizer_forpass_form")
def coOrganizer_forpass_form():
    return render_template('coOrganizer_forpass_form.html')

#Co-Organizer change password after otp verification
@app.route('/change_coOrganizer_pass',methods=['POST'])
def change_coOrganizer_pass():
    if request.method == "POST":
        if 'coorganizer' in session:
            pass1 = request.form['pass1']
            flag = 0
            while True:  
                if (len(pass1)<8):
                    flag = -1
                    break
                elif not re.search("[a-z]", pass1):
                    flag = -1
                    break
                elif not re.search("[A-Z]", pass1):
                    flag = -1
                    break
                elif not re.search("[0-9]", pass1):
                    flag = -1
                    break
                elif not re.search("[_@$]", pass1):
                    flag = -1
                    break
                elif re.search("\\s", pass1):
                    flag = -1
                    break
                else:
                    flag = 0
                    break
            if flag ==-1:
                flash("Not a Valid Password","error")
                return redirect(url_for("coOrganizer_forpass_form"))
            pass2 = request.form['pass2']
            if pass1 == pass2:
                hash_pass = sha256_crypt.hash(pass1)
                data = Coorganizer.query.filter_by(email=session['email']).first()
                data.password = hash_pass
                db.session.commit()
                session.pop('coorganizer',None)
                session.pop('email',None)
                flash("Password changed successfully","success")
                return redirect(url_for("coOrganizer_log"))
            else:
                flash("Passwords dont match",'error')
                return redirect(url_for('coOrganizer_forpass_form'))
        else:
            flash("Session Expired","error")
            return redirect(url_for('coOrganizer_log'))
    else:
        session.clear()
        flash('Unauthorized access','error')
        return redirect(url_for('home'))

@app.route("/coOrganizer_view_event")
def coOrganizer_view_event():
    if 'coorganizer' in session:
        events = Event.query.filter_by(coorg_mail=session['coorganizer_email'])
        return render_template('coOrganizer_view_event.html',data=events)
    else:
        flash("Session Expired","error")
        return redirect(url_for('coOrganizer_log'))

@app.route("/coOrganizer_event_page/<int:id>",methods=['POST'])
def coOrganizer_event_page(id):
    if 'coorganizer' in session:
        get_event_data = Event.query.filter_by(id=id).first()
        return render_template('coOrganizer_event_page.html',data=get_event_data)
    else:
        flash("Session Expired","error")
        return redirect(url_for('coOrganizer_log'))

@app.route("/coOrganizer_event_update/<int:id>",methods=['GET','POST'])
def coOrganizer_event_update(id):
    if 'coorganizer' in session:
        event = Event.query.filter_by(id=id).first()
        judge = Judge.query.all()
        return render_template('coOrganizer_event_update.html',data=event,judge=judge)
    else:
        flash("Session Expired","error")
        return redirect(url_for('coOrganizer_log'))

@app.route("/coOrganizer_update_event/<int:id>",methods=["POST"])
def coOrganizer_update_event(id):
    if request.method == 'POST':
        if 'coorganizer' in session:
            event = Event.query.filter_by(id=id).first()
            name = request.form['name']
            description = request.form['description']     
            date = request.form['date']
            time = request.form['time']
            category = request.form['category']
            name_check = Event.query.filter_by(name=name).first()
            if not name_check:
                event.name = name
                event.description = description
                event.date = date
                event.time = time
                event.category = category
                db.session.commit()
                flash('Event updated successfully','success')
                return redirect(url_for('coOrganizer_view_event'))
            elif name_check.id == id:
                event.description = description
                event.date = date
                event.time = time
                event.category = category
                db.session.commit()
                flash('Event updated successfully','success')
                return redirect(url_for('coOrganizer_view_event'))
            else: 
                flash("Name already used","error")
                return redirect(url_for('coOrganizer_view_event'))
        else:
            flash("Session Expired","error")
            return redirect(url_for('coOrganizer_log'))
    else:
        session.clear()
        flash('Unauthorized access','error')
        return redirect(url_for('home'))

@app.route("/judge")
def judge():
    if 'coorganizer' in session:
        events = Event.query.filter_by(coorg_mail=session['coorganizer_email']).all()
        if not events:
            flash("No events assigned to you","error")
            return redirect(url_for('coOrganizerdash'))
        else:
            return render_template('add_judge.html',data=events)
    else:
        flash("Session Expired","error")
        return redirect(url_for('coOrganizer_log'))

@app.route("/add_judge",methods=["POST"])
def add_judge():
    if request.method == 'POST':
        if 'coorganizer' in session:
            name = request.form['name']
            email = request.form['email']     
            event = request.form['event']  
            email_check = Judge.query.filter_by(email=email).first()
            event_data = Event.query.filter_by(name=event).first()
            if not email_check:
                name_check = Judge.query.filter_by(name=name).first()
                if not name_check:
                    hash_pass = sha256_crypt.hash(email)
                    judge = Judge(name=name,email=email,password=hash_pass,event=event)
                    event_data.judge = name
                    db.session.add(judge)
                    db.session.commit()
                    flash('Judge added successfully','success')
                    return redirect(url_for('coOrganizerdash'))
                else:
                    flash("Name already used","error")
                    return redirect(url_for('judge'))
            else:
                flash("Email ID already used","error")
                return redirect(url_for('judge'))
        else:
            flash("Session Expired","error")
            return redirect(url_for('coOrganizerlog'))
    else:
        session.clear()
        flash('Unauthorized access','error')
        return redirect(url_for('home'))

#participant view event
@app.route("/participant_view_event")
def participant_view_event():
    if 'participant' in session:
        events = Event.query.all()
        return render_template('participant_view_event.html',data=events)
    else:
        flash("Session Expired","error")
        return redirect(url_for('participantlog'))

#participant reg event
@app.route("/participant_event_register/<int:id>",methods=['GET','POST'])
def participant_event_register(id):
    if 'participant' in session:
        part_id=session['participant_id']
        entry_check = Plist.query.filter_by(part_id=part_id,event_id=id).first()
        if entry_check is None:
            part = Plist(part_id=part_id,event_id=id)
            db.session.add(part)
            db.session.commit()
            flash('Registration Sucessful for event','success')
            return redirect(url_for('participant_view_event'))
        else:
            flash('Already Registered','error')
            return redirect(url_for('participant_view_event'))

    else:
        flash("Session Expired","error")
        return redirect(url_for('participantlog'))

#logout function for all
@app.route("/logout")
def logout():
    session.clear()
    flash('Logged out successfully',"success")
    return redirect(url_for("home"))


if __name__ == '__main__':
    app.run(debug=True,port=9876)
