from app import db

class Storage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    submitdate = db.Column()
    submitcount = db.Column()
    filename = db.Column()
    filesize = db.Column()
    filepath = db.Column()
    md5 = db.Column()
    sha256 = db.Column()
    virustotal = db.Column()
    clamav = db.Column()
    yararules = db.Column()
    compressedsize = db.Column()
    hexdump = db.Column(db.Text())
    strings = db.Column(db.Text())
    pedll = db.Column(db.Text())
    pesections = db.Column(db.Text())
    pedump = db.Column(db.Text())

    def __repr__(self):
        return '<Storage {}>'.format(self.filename)

