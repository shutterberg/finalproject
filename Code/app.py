from flask import *
from flask_sqlalchemy import SQLAlchemy
from passlib.hash import sha256_crypt
import os,random,re
from datetime import timedelta
from flask_mail import Mail,Message

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(16)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///event_db.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config['SESSION_COOKIE_NAME'] = 'login-system'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)

app.config['MAIL_SERVER'] = 'smtp-mail.outlook.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_participantNAME'] = "eventxsjec@outlook.com"
app.config['MAIL_PASSWORD'] = "#Eventx18"
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

#client_id="505348922138-a10mfp737qq5lmgi33opfis1ln0cka5j.apps.googleusercontent.com",
#client_secret='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',

db = SQLAlchemy(app)
mail = Mail(app)

#creating tables
class Organizer(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    name = db.Column(db.String(50),nullable=False)
    email = db.Column(db.String(100),nullable=False,unique=True)
    phone = db.Column(db.String(11), nullable=False, unique=True)
    password = db.Column(db.String(255),nullable=False)
    organization = db.Column(db.String(255),nullable=False)

    def __repr__(self):
        return '<Organizer %r>' % self.email

class Participant(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    name = db.Column(db.String(50),nullable=False)
    email = db.Column(db.String(100),nullable=False,unique=True)
    phone = db.Column(db.String(11), nullable=False, unique=True)
    password = db.Column(db.String(255),nullable=False)
    category = db.Column(db.String(50),nullable=False)
    event_id = db.Column(db.Integer,nullable=True,unique=True)

    def __repr__(self):
        return '<Participant %r>' % self.email

class Organization(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    name = db.Column(db.String(50),nullable=False)
    email = db.Column(db.String(100),nullable=False,unique=True)
    location = db.Column(db.String(100),nullable=False)

    def __repr__(self):
        return '<Organization %r>' % self.email

#db.create_all()
#db.drop_all()

#home page
@app.route("/")
def home():
    return render_template('home.html')

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
                msg = Message("Registration Confirmation",sender="eventxsjec@outlook.com",recipients=[email])
                msg.body = "Thank you for registering on our website.Hope you have a good experience"
                mail.send(msg)
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
            msg = Message('OTP for Password change',sender="eventxsjec@outlook.com",recipients=[email])
            msg.body = "Dear participant, your verification code is: " + str(otp)
            mail.send(msg)
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
                    msg = Message("Your are a Organizer!",sender="eventxsjec@outlook.com",recipients=[email])
                    msg.body = "You have been successfully added as a ORGANIZER under the organization "+str(organization).upper()+". Please use your email as your password on your first login and change it by clicking the update profile option"
                    mail.send(msg)
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


#logout function for all
@app.route("/logout")
def logout():
    session.clear()
    flash('Logged out successfully',"success")
    return redirect(url_for("home"))

if __name__ == '__main__':
    app.run(debug=True,port=9876)
