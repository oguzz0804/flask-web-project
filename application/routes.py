from application import app
from flask import render_template, url_for, redirect,flash,request
from flask_material import Material
from application.form import UserDataForm
from application.models import IncomeExpenses
from application import db
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import json
import pandas as pd
import numpy as np
from sklearn.externals import joblib
from math import sqrt

Material(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
bcrypt = Bcrypt(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    

class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')


class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')


@app.route('/',methods=['GET', 'POST'])
@login_required
def index():
    entries = IncomeExpenses.query.order_by(IncomeExpenses.type.desc()).all()   
    income = db.select([IncomeExpenses]).where(IncomeExpenses.type =='income')
    #a1 = [1,2,3,4,5,6]
    #a2 = [1,2,3,4,5,7]
    #sum = 0
    #suma1 = 0
    #sumb1 = 0    
    #for i,j in zip(a1,a2):
        #suma1 += i*i
        #sumb1 += j*j
        #sum += i*j
        #cosinesim = sum / ((sqrt(suma1))*(sqrt(sumb1)))
    return render_template('index.html', entries = entries)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('index'))
    return render_template('login.html', form=form)

@app.route('/add', methods = ["POST", "GET"])
@login_required
def add_expense():
    form = UserDataForm()
    if form.validate_on_submit():
        entry = IncomeExpenses(type=form.type.data, category=form.category.data, amount=form.amount.data)
        db.session.add(entry)
        db.session.commit()
        flash(f"{form.type.data} has been added to {form.type.data}s", "success")
        return redirect(url_for('index'))
    return render_template('add.html', title="Add expenses", form=form)


@app.route('/delete-post/<int:entry_id>')
def delete(entry_id):
    entry = IncomeExpenses.query.get_or_404(int(entry_id))
    db.session.delete(entry)
    db.session.commit()
    flash("Entry deleted", "success")
    return redirect(url_for("index"))


@app.route('/dashboard')
@login_required
def dashboard():
    income_vs_expense = db.session.query(db.func.sum(IncomeExpenses.amount), IncomeExpenses.type).group_by(IncomeExpenses.type).order_by(IncomeExpenses.type).all()

    category_comparison = db.session.query(db.func.sum(IncomeExpenses.amount), IncomeExpenses.category).group_by(IncomeExpenses.category).order_by(IncomeExpenses.category).all()

    dates = db.session.query(db.func.sum(IncomeExpenses.amount), IncomeExpenses.date).group_by(IncomeExpenses.date).order_by(IncomeExpenses.date).all()

    income_category = []
    for amounts, _ in category_comparison:
        income_category.append(amounts)

    income_expense = []
    for total_amount, _ in income_vs_expense:
        income_expense.append(total_amount)

    over_time_expenditure = []
    dates_label = []
    for amount, date in dates:
        dates_label.append(date.strftime("%m-%d-%y"))
        over_time_expenditure.append(amount)

    return render_template('dashboard.html',
                            income_vs_expense=json.dumps(income_expense),
                            income_category=json.dumps(income_category),
                            over_time_expenditure=json.dumps(over_time_expenditure),
                            dates_label =json.dumps(dates_label)
                        )
    
    
@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


@app.route('/decision_tree')
@login_required
def dtree():
    return render_template("decision_tree.html")

@app.route('/preview')
@login_required
def preview():
    df = pd.read_csv('iris.csv')
    return render_template("preview.html",df_view = df)

@app.route('/analyze',methods=['POST'])
def analyze():
    if request.method == 'POST':
        petal_length = request.form['petal_length']
        sepal_length = request.form['sepal_length']
        petal_width = request.form['petal_width']
        sepal_width = request.form['sepal_width']
        model_choice = request.form['model_choice']
        
        sample_data = [sepal_length,sepal_width,petal_length,petal_width]
        
        clean_data = [float(i) for i in sample_data]
        
        ex1 = np.array(clean_data).reshape(1,-1)
        
        #ex1 = np.array(ex1).reshape(1,-1)
        
        if model_choice == 'logitmodel':
            logit_model = joblib.load('logit_model_iris.pkl')
            result_prediction = logit_model.predict(ex1)
        elif model_choice == 'knnmodel':
            knn_model = joblib.load('knn_model_iris.pkl')
            result_prediction = knn_model.predict(ex1)
        elif model_choice == 'svmmodel':
            svm_model = joblib.load('svm_model_iris.pkl')
            result_prediction = svm_model.predict(ex1)
        else:
            logit_model = joblib.load('logit_model_iris.pkl')
            result_prediction = logit_model.predict(ex1)
        
    return render_template("decision_tree.html",sepal_length =sepal_length,
                           sepal_width =sepal_width,
                           petal_length = petal_length,
                           petal_width = petal_width,
                           clean_data = clean_data,
                           result_prediction = result_prediction,
                           model_selected = model_choice)