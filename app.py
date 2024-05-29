# this is the basic syntax of flask app
from flask import Flask, request, render_template, request, redirect, url_for, flash, session
from werkzeug.security import check_password_hash, generate_password_hash
import pickle #to load the model and scaler
from flask_sqlalchemy import SQLAlchemy
import numpy as np
import bcrypt

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
app.secret_key = 'secret_key' #secret key for cookie 

# # Dummy user data for demonstration purposes
# users = {
#     'admin': generate_password_hash('password')  # Generate hashed password for 'admin'
# }


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(100))

    def __init__(self,password,username):
        self.username = username
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    def check_password(self,password):
        return bcrypt.checkpw(password.encode('utf-8'),self.password.encode('utf-8'))

with app.app_context():
    db.create_all()


model = pickle.load(open('modelF/rf_classifier.pkl', 'rb')) #read binary mode
scaler = pickle.load(open('modelF/scaler.pkl', 'rb'))


#same predict function that we defined earlier to predict the values
#here basically we get all the values from the form and use the predict function to calculate the prediction
def predict(model, scaler, male, age, currentSmoker, cigsPerDay, BPMeds, prevalentStroke, prevalentHyp, diabetes,
            totChol, sysBP, diaBP, BMI, heartRate, glucose):
    # Encode categorical variables
    male_encoded = 1 if male.lower() == "male" else 0
    currentSmoker_encoded = 1 if currentSmoker.lower() == "yes" else 0
    BPMeds_encoded = 1 if BPMeds.lower() == "yes" else 0
    prevalentStroke_encoded = 1 if prevalentStroke.lower() == "yes" else 0
    prevalentHyp_encoded = 1 if prevalentHyp.lower() == "yes" else 0
    diabetes_encoded = 1 if diabetes.lower() == "yes" else 0

    # Prepare features array
    features = np.array([[male_encoded, age, currentSmoker_encoded, cigsPerDay, BPMeds_encoded, prevalentStroke_encoded,
                          prevalentHyp_encoded, diabetes_encoded, totChol, sysBP, diaBP, BMI, heartRate, glucose]])

    # Scale the features
    scaled_features = scaler.transform(features)

    # Predict using the model
    result = model.predict(scaled_features)

    return result[0]


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # handle request
        username = request.form['username']
        password = request.form['password']

        new_user = User(username=username,password=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect('/login')



    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            session['username'] = user.username
            return redirect('/home')
        else:
            return render_template('login.html',error='Invalid user')

    return render_template('login.html')

@app.route('/home')
def home():
    if session['username']:
        user = User.query.filter_by(username=session['username']).first()
        return render_template('home.html',user=user)
    
    return redirect('/login')


#as form m action pred tha or method post
@app.route("/pred", methods=['GET','POST'])
def pred():
    if request.method=='POST':
        # request from the form using the name assigned there as the div of gender is assigned name male so it is accessed this way here
        gender = request.form.get('gender')
        age = int(request.form['age'])
        currentSmoker = request.form['currentSmoker']
        cigsPerDay = float(request.form['cigsPerDay'])
        BPMeds = request.form['BPMeds']
        prevalentStroke = request.form['prevalentStroke']
        prevalentHyp = request.form['prevalentHyp']
        diabetes = request.form['diabetes']
        totChol = float(request.form['totChol'])
        sysBP = float(request.form['sysBP'])
        diaBP = float(request.form['diaBP'])
        BMI = float(request.form['BMI'])
        heartRate = float(request.form['heartRate'])
        glucose = float(request.form['glucose'])

        prediction = predict(model, scaler, gender, age, currentSmoker, cigsPerDay, BPMeds, prevalentStroke, prevalentHyp, diabetes, totChol, sysBP, diaBP, BMI, heartRate, glucose)
        prediction_text = "The Patient has Heart Disease" if prediction == 1 else "The Patient has No Heart Disease"
        
        #return the message to home.html message of the prediction
        return render_template('home.html', prediction=prediction_text)


@app.route('/logout')
def logout():
    session.pop('username',None)
    return redirect('/login')


if __name__ =='__main__':
    app.run(debug=True)
