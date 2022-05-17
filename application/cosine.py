from application import db

class CosineSim(db.Model):
    v1 = db.Column(db.Integer, nullable=False)
    v2 = db.Column(db.Integer, nullable=False) 