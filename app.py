import os, io, subprocess
from datetime import datetime
from functools import wraps

# Flask ve eklentiler
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, abort, send_file
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    current_user, login_required
)
from werkzeug.utils import secure_filename
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, TextAreaField, IntegerField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo, NumberRange
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth
from sqlalchemy import func

# Optional: WeasyPrint integration
try:
    from weasyprint import HTML, CSS
    WEASYPRINT_AVAILABLE = True
except Exception:
    WEASYPRINT_AVAILABLE = False

# --- App Config ---
app = Flask(__name__)
app.config["SECRET_KEY"] = "change-this-secret-in-production"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///codexia.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Veritabanı ve Login Yöneticisi Başlatma
db = SQLAlchemy(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Bu sayfayı görüntülemek için giriş yapmalısınız."
login_manager.login_message_category = "info"


# --- User Loader ---
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))



# --- User ---
class User(db.Model, UserMixin):
    __tablename__ = "users"
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=True, index=True) # EKLENDİ
    fullname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=True)
    phone = db.Column(db.String(20))
    role = db.Column(db.String(20), default="user")  # "user" or "admin"
    auth_provider = db.Column(db.String(50), default="local")
    _is_active = db.Column("is_active", db.Boolean, default=True)  # private field
    is_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = db.Column(db.DateTime)

    # İlişkiler
    orders = db.relationship("Order", back_populates="user", lazy=True, cascade="all, delete-orphan")
    wishlist_items = db.relationship("WishlistItem", back_populates="user", lazy=True, cascade="all, delete-orphan")
    reviews = db.relationship("Review", back_populates="user", lazy=True, cascade="all, delete-orphan")
    cart_items = db.relationship("CartItem", back_populates="user", lazy=True, cascade="all, delete-orphan")

    # Flask-Login uyumlu property
    @property
    def is_active(self):
        return self._is_active

    @is_active.setter
    def is_active(self, value: bool):
        self._is_active = value

    def set_password(self, raw):
        self.password_hash = generate_password_hash(raw)

    def check_password(self, raw):
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, raw)

    def is_admin(self):
        return self.role == "admin"


# --- Category ---
class Category(db.Model):
    __tablename__ = "categories"
    __table_args__ = {'extend_existing': True}
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.Text)
    products = db.relationship("Product", back_populates="category", lazy=True, cascade="all, delete-orphan")


# --- Campaign ---
class Campaign(db.Model):
    __tablename__ = "campaigns"
    __table_args__ = {'extend_existing': True}
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text)
    discount = db.Column(db.Integer, default=0)
    image_url = db.Column(db.String(250))
    products = db.relationship("Product", back_populates="campaign", lazy=True)


# --- Product ---
class Product(db.Model):
    __tablename__ = "products"
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Float, nullable=False)
    image_url = db.Column(db.String(250))
    category_id = db.Column(db.Integer, db.ForeignKey("categories.id"), nullable=False)
    campaign_id = db.Column(db.Integer, db.ForeignKey("campaigns.id"))

    # Stok ve Durum
    stock = db.Column(db.Integer, default=0)
    sku = db.Column(db.String(50), unique=True, index=True)
    brand = db.Column(db.String(100))
    discount = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)
    supplier = db.Column(db.String(100))
    slug = db.Column(db.String(150), index=True)  # unique kaldırıldı

    # SEO alanları
    seo_title = db.Column(db.String(150))
    seo_description = db.Column(db.String(250))

    # Ek bilgiler
    shipping_info = db.Column(db.String(250))
    weight = db.Column(db.Float)
    dimensions = db.Column(db.String(100))
    warranty = db.Column(db.String(50))
    tags = db.Column(db.String(250))
    features = db.Column(db.Text)
    variants = db.Column(db.Text)

    # İstatistikler
    rating = db.Column(db.Float, default=0.0)
    review_count = db.Column(db.Integer, default=0)
    sales_count = db.Column(db.Integer, default=0)
    wishlist_count = db.Column(db.Integer, default=0)

    # İlişkiler
    campaign = db.relationship("Campaign", back_populates="products")
    category = db.relationship("Category", back_populates="products")
    cart_items = db.relationship("CartItem", back_populates="product", lazy=True, cascade="all, delete-orphan")
    reviews = db.relationship("Review", back_populates="product", lazy=True, cascade="all, delete-orphan")
    wishlist_entries = db.relationship("WishlistItem", back_populates="product", lazy=True, cascade="all, delete-orphan")
    order_items = db.relationship("OrderItem", back_populates="product", lazy=True, cascade="all, delete-orphan")

    # 🔧 Ekstra: kampanya indirimi otomatik hesaplama
    @property
    def effective_discount(self):
        """Ürünün geçerli indirim oranı (kampanya varsa kampanya indirimini kullanır)."""
        if self.campaign:
            return self.campaign.discount
        return self.discount

    @property
    def discounted_price(self):
        """İndirimli fiyatı hesaplar."""
        return self.price * (1 - self.effective_discount / 100)

# --- Proposal ---
class Proposal(db.Model):
    __tablename__ = "proposals"
    __table_args__ = {'extend_existing': True}
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    customer_name = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(50), default="Taslak")
    total_price = db.Column(db.Float, default=0.0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    items = db.relationship("ProposalItem", back_populates="proposal", lazy=True, cascade="all, delete-orphan")


class ProposalItem(db.Model):
    __tablename__ = "proposal_items"
    __table_args__ = {'extend_existing': True}
    id = db.Column(db.Integer, primary_key=True)
    proposal_id = db.Column(db.Integer, db.ForeignKey("proposals.id"), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    unit = db.Column(db.String(50))
    quantity = db.Column(db.Float, default=0.0)
    unit_price = db.Column(db.Float, default=0.0)
    is_labor = db.Column(db.Boolean, default=False)

    @property
    def subtotal(self):
        return self.quantity * self.unit_price

    proposal = db.relationship("Proposal", back_populates="items")


# --- Cart ---
class CartItem(db.Model):
    __tablename__ = "cart_items"
    __table_args__ = {'extend_existing': True}
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    product_id = db.Column(db.Integer, db.ForeignKey("products.id"), nullable=False, index=True)
    quantity = db.Column(db.Integer, default=1, nullable=False)

    user = db.relationship("User", back_populates="cart_items")
    product = db.relationship("Product", back_populates="cart_items")


# --- Review ---
class Review(db.Model):
    __tablename__ = "reviews"
    __table_args__ = {'extend_existing': True}
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey("products.id"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    rating = db.Column(db.Integer, nullable=False)  # 1..5
    comment = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", back_populates="reviews")
    product = db.relationship("Product", back_populates="reviews")


# --- Wishlist ---
class WishlistItem(db.Model):
    __tablename__ = "wishlist_items"
    __table_args__ = {'extend_existing': True}
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    product_id = db.Column(db.Integer, db.ForeignKey("products.id"), nullable=False, index=True)

    user = db.relationship("User", back_populates="wishlist_items")
    product = db.relationship("Product", back_populates="wishlist_entries")


# --- Order ---
# --- Order ---
class Order(db.Model):
    __tablename__ = "orders"
    __table_args__ = {'extend_existing': True}
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    total_price = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(50), default="Hazırlanıyor")  # "Hazırlanıyor", "Tamamlandı", "İptal"
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # İlişkiler
    user = db.relationship("User", back_populates="orders")
    items = db.relationship("OrderItem", back_populates="order", lazy=True, cascade="all, delete-orphan")

    def calculate_total(self):
        """Sipariş toplamını item’lardan hesaplar."""
        return sum(item.subtotal for item in self.items)


class OrderItem(db.Model):
    __tablename__ = "order_items"
    __table_args__ = {'extend_existing': True}

    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey("orders.id"), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey("products.id"), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    unit_price = db.Column(db.Float, nullable=False)

    @property
    def subtotal(self):
        return self.quantity * self.unit_price

    # İlişkiler
    order = db.relationship("Order", back_populates="items")
    product = db.relationship("Product", back_populates="order_items")
# --- Forms ---

class LoginForm(FlaskForm):

    email = StringField("E-posta", validators=[DataRequired(), Email(), Length(max=120)])

    password = PasswordField("Şifre", validators=[DataRequired(), Length(min=6, max=128)])





class RegisterForm(FlaskForm):

    fullname = StringField("Ad Soyad", validators=[DataRequired(), Length(min=2, max=100)])

    email = StringField("E-posta", validators=[DataRequired(), Email(), Length(max=120)])

    password = PasswordField("Şifre", validators=[DataRequired(), Length(min=6, max=128)])

    confirm_password = PasswordField("Şifre Tekrar", validators=[DataRequired(), EqualTo("password")])





class ContactForm(FlaskForm):

    fullname = StringField("Ad Soyad", validators=[DataRequired(), Length(min=2, max=100)])

    email = StringField("E-posta", validators=[DataRequired(), Email(), Length(max=120)])

    message = TextAreaField("Mesaj", validators=[DataRequired(), Length(min=10, max=2000)])





class CheckoutForm(FlaskForm):

    fullname = StringField("Ad Soyad", validators=[DataRequired(), Length(min=2, max=100)])

    address = TextAreaField("Adres", validators=[DataRequired(), Length(min=10, max=1000)])

    phone = StringField("Telefon", validators=[DataRequired(), Length(min=10, max=20)])

    card_number = StringField("Kart Numarası", validators=[DataRequired(), Length(min=12, max=25)])

    expiry = StringField("Son Kullanma", validators=[DataRequired(), Length(min=4, max=7)])

    cvv = StringField("CVV", validators=[DataRequired(), Length(min=3, max=4)])

    submit = SubmitField("Ödemeyi Tamamla")

class AddToCartForm(FlaskForm):

    quantity = IntegerField(

        "Adet",

        validators=[DataRequired(), NumberRange(min=1)]

    )

    submit = SubmitField("Sepete Ekle")

   

class ReviewForm(FlaskForm):

    rating = IntegerField(

        "Puan",

        validators=[DataRequired(), NumberRange(min=1, max=5)]

    )

    comment = TextAreaField(

        "Yorum",

        validators=[DataRequired(), Length(min=5)]

    )

    submit = SubmitField("Yorum Gönder")      
class CategoryForm(FlaskForm):
    name = StringField("Kategori Adı", validators=[DataRequired()])
    description = TextAreaField("Açıklama")
    submit = SubmitField("Kaydet")


from flask_wtf import FlaskForm

from wtforms import SubmitField



class WishlistForm(FlaskForm):

    submit = SubmitField("Favorilere Ekle")      

from authlib.integrations.flask_client import OAuth

# --- Helpers ---
from authlib.integrations.flask_client import OAuth


oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id='your client id',
    client_secret='your client secret',
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'},
)

@app.route('/login/google')
def login_google():
    redirect_uri = url_for('authorize_google', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/authorize/google')
def authorize_google():
    token = google.authorize_access_token()
    # Doğru endpoint: discovery’den otomatik geliyor
    resp = google.get('https://openidconnect.googleapis.com/v1/userinfo')
    user_info = resp.json()

    # Kullanıcıyı DB’de bul veya oluştur
 
    user = User.query.filter_by(email=user_info['email']).first()
    if not user:
        user = User(fullname=user_info['name'],
                    email=user_info['email'],
                    auth_provider="google")  # şifre yok
        db.session.add(user)
        db.session.commit()
    login_user(user)
    flash("Google ile giriş yapıldı.", "success")
    return redirect(url_for("index"))

# --- Facebook OAuth Register ---
facebook = oauth.register(
    name="facebook",
    client_id="your client id",
    client_secret="your client secret",
    access_token_url="https://graph.facebook.com/v12.0/oauth/access_token",
    authorize_url="https://www.facebook.com/v12.0/dialog/oauth",
    api_base_url="https://graph.facebook.com/v12.0/",
    client_kwargs={"scope": "email public_profile"},
)

# --- Facebook Login Route ---
@app.route("/login/facebook")
def login_facebook():
    redirect_uri = url_for("authorize_facebook", _external=True)
    return facebook.authorize_redirect(redirect_uri)

@app.route("/authorize/facebook")
def authorize_facebook():
    token = facebook.authorize_access_token()
    resp = facebook.get("me?fields=id,name,email")
    user_info = resp.json()

    # Kullanıcıyı DB’de bul veya oluştur
    user = User.query.filter_by(email=user_info.get("email")).first()
    if not user:
        user = User(
            fullname=user_info.get("name"),
            email=user_info.get("email"),
            auth_provider="facebook"
        )
        db.session.add(user)
        db.session.commit()

    login_user(user)
    flash("Facebook ile giriş yapıldı.", "success")
    return redirect(url_for("index"))

# --- Auth helpers & decorators ---
def current_user():
    email = session.get("user_email")
    if not email:
        return None
    return User.query.filter_by(email=email).first()

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user:
            flash("Lütfen giriş yapın.", "info")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = current_user
        if not user or user.role != "admin":
            flash("Bu alana erişim izniniz yok.", "warning")
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return wrapper
# Kampanya Ürün Yönetimi
@app.route("/admin/campaigns/<int:cid>/products", methods=["GET", "POST"])
@admin_required
def admin_campaign_products(cid):
    campaign = Campaign.query.get_or_404(cid)
    all_products = Product.query.filter(
        (Product.campaign_id.is_(None)) | (Product.campaign_id == cid)
    ).all()

    if request.method == "POST":
        product_id = int(request.form["product_id"])
        product = Product.query.get_or_404(product_id)
        product.campaign_id = cid
        db.session.commit()
        flash(f"Ürün '{product.name}' kampanyaya eklendi.", "success")
        return redirect(url_for("admin_campaign_products", cid=cid))

    return render_template("admin_campaign_products.html", campaign=campaign, all_products=all_products)


# Kampanyadan Ürün Çıkarma
@app.route("/admin/campaigns/<int:cid>/products/remove/<int:pid>", methods=["POST"])
@admin_required
def admin_campaign_remove_product(cid, pid):
    product = Product.query.get_or_404(pid)
    if product.campaign_id == cid:
        product.campaign_id = None
        db.session.commit()
        flash(f"Ürün '{product.name}' kampanyadan çıkarıldı.", "warning")
    return redirect(url_for("admin_campaign_products", cid=cid))

# --- Initial DB setup with demo data ---
# --- Search ---
@app.route("/search")
def search():
    q = request.args.get("q", "").strip()
    results = []
    if q:
        results = Product.query.filter(Product.name.ilike(f"%{q}%")).all()
    return render_template("search_results.html", query=q, results=results)


# --- DB Seed (uygulama başlatıldığında)
with app.app_context():
    db.create_all()

    # Admin kullanıcı
    if not User.query.filter_by(email="admin@codexia.com").first():
        admin = User(fullname="Admin", email="admin@codexia.com", phone="0000", role="admin")
        admin.set_password("admin123")
        db.session.add(admin)

    # Demo kullanıcı
    if not User.query.filter_by(email="demo@codexia.com").first():
        user = User(fullname="Demo Kullanıcı", email="demo@codexia.com", phone="0555 555 55 55", role="user")
        user.set_password("demo123")
        db.session.add(user)

    # Kategoriler ve ürünler
    if Category.query.count() == 0:
        cat1 = Category(name="Elektronik", description="Telefon, bilgisayar ve aksesuarlar")
        cat2 = Category(name="Aksesuar", description="Kulaklık, saat ve benzeri ürünler")
        db.session.add_all([cat1, cat2])
        db.session.flush()  # id'leri almak için

        products = [
            Product(
                name="Akıllı Telefon",
                price=19999.90,
                image_url="/static/img/phone.jpg",
                description="Yüksek performanslı akıllı telefon.",
                category_id=cat1.id,
                sku="TEL-001",
                brand="Codexia Mobile",
                discount=10,
                stock=50,
                shipping_info="2-4 iş günü içinde kargoda",
                weight=0.5,
                dimensions="15x7x0.8 cm",
                warranty="2 yıl",
                supplier="Codexia Teknoloji",
                slug="akilli-telefon",
                tags="telefon,akıllı,elektronik",
                features="128GB hafıza, 8GB RAM, AMOLED ekran",
                variants="Renk: Siyah,Beyaz"
            ),
            Product(
                name="Dizüstü Bilgisayar",
                price=34999.00,
                image_url="/static/img/laptop.jpg",
                description="Profesyoneller için güçlü laptop.",
                category_id=cat1.id,
                sku="LAP-001",
                brand="Codexia Pro",
                discount=15,
                stock=30,
                shipping_info="3-5 iş günü içinde kargoda",
                weight=2.2,
                dimensions="35x24x2 cm",
                warranty="2 yıl",
                supplier="Codexia Teknoloji",
                slug="dizustu-bilgisayar",
                tags="bilgisayar,laptop,elektronik",
                features="Intel i7, 16GB RAM, 512GB SSD",
                variants="Renk: Gri"
            ),
            Product(
                name="Kulaklık",
                price=1299.99,
                image_url="/static/img/headphones.jpg",
                description="Gürültü engelleme özelliği.",
                category_id=cat2.id,
                sku="ACC-001",
                brand="Codexia Sound",
                discount=5,
                stock=100,
                shipping_info="1-2 iş günü içinde kargoda",
                weight=0.3,
                dimensions="20x18x8 cm",
                warranty="1 yıl",
                supplier="Codexia Aksesuar",
                slug="kulaklik",
                tags="kulaklık,aksesuar,müzik",
                features="Bluetooth 5.0, ANC, 20 saat pil",
                variants="Renk: Siyah,Kırmızı"
            ),
            Product(
                name="Akıllı Saat",
                price=4999.00,
                image_url="/static/img/watch.jpg",
                description="Sağlık takip ve bildirimler.",
                category_id=cat2.id,
                sku="ACC-002",
                brand="Codexia Watch",
                discount=0,
                stock=75,
                shipping_info="2-3 iş günü içinde kargoda",
                weight=0.1,
                dimensions="4x4x1 cm",
                warranty="2 yıl",
                supplier="Codexia Aksesuar",
                slug="akilli-saat",
                tags="saat,akıllı,aksesuar",
                features="Kalp ritmi ölçer, GPS, Su geçirmez",
                variants="Renk: Siyah,Gümüş"
            ),
        ]
        db.session.add_all(products)

    # Kampanyalar
    if Campaign.query.count() == 0:
        db.session.add_all([
            Campaign(title="Yeni Yıl İndirimi", description="Seçili ürünlerde %20 indirim!", discount=20,
                     image_url="/static/img/campaign1.jpg"),
            Campaign(title="Hafta Sonu Fırsatı", description="Kargo bedava!", discount=0,
                     image_url="/static/img/campaign2.jpg"),
        ])

    db.session.commit()


# --- Utility: cart stored in DB ---
def cart_items():
    """Aktif kullanıcının sepetindeki ürünleri döndürür."""
    items = []
    cart_items_raw = CartItem.query.filter_by(user_id=current_user.id).all()
    for ci in cart_items_raw:
        product = ci.product
        if product and ci.quantity > 0:
            items.append({
                "id": ci.id,
                "name": product.name,
                "price": product.price,
                "quantity": ci.quantity,
                "image_url": product.image_url or "",
                "seller": product.supplier,
                "original_price": product.price + (product.discount or 0),
                "subtotal": product.price * ci.quantity,
                "shipping_cost": 0.0
            })
    return items


def cart_total():
    """Sepetteki ürünlerin toplam tutarını döndürür."""
    return sum(i["subtotal"] for i in cart_items())


# --- Routes ---
@app.route("/")
def index():
    products = Product.query.filter_by(is_active=True).all()
    flash_products = [p for p in products if p.discount >= 20]
    trending_products = Product.query.order_by(Product.sales_count.desc()).limit(8).all()
    brands = sorted(set(p.brand for p in products if p.brand))
    user_favorites = []

    if current_user.is_authenticated:
        fav_ids = [item.product_id for item in WishlistItem.query.filter_by(user_id=current_user.id).all()]
        user_favorites = Product.query.filter(Product.id.in_(fav_ids)).all()

    return render_template("index.html",
                           products=products,
                           flash_products=flash_products,
                           trending_products=trending_products,
                           user_favorites=user_favorites,
                           brands=brands)

@app.route("/category")
def category_list():
    categories = Category.query.all()
    return render_template("category.html", categories=categories)


from flask import request

@app.route("/category/<int:cid>")
def category_detail(cid):
    cat = Category.query.get_or_404(cid)

    # Filtre parametreleri
    brand = request.args.get("brand")
    sort = request.args.get("sort")
    min_price = request.args.get("min_price", type=float)
    max_price = request.args.get("max_price", type=float)

    query = Product.query.filter_by(category_id=cid, is_active=True)

    if brand:
        query = query.filter(Product.brand == brand)
    if min_price is not None:
        query = query.filter(Product.price >= min_price)
    if max_price is not None:
        query = query.filter(Product.price <= max_price)

    # Sıralama
    if sort == "price_asc":
        query = query.order_by(Product.price.asc())
    elif sort == "price_desc":
        query = query.order_by(Product.price.desc())
    elif sort == "discount_desc":
        query = query.order_by(Product.discount.desc())

    products = query.all()

    # Markaları filtre dropdown için çekelim
    brands = db.session.query(Product.brand).filter_by(category_id=cid).distinct().all()
    brands = [b[0] for b in brands if b[0]]

    return render_template("category_detail.html",
                           category=cat,
                           products=products,
                           brands=brands)

# --- Rating Utility ---
from sqlalchemy import func

def recalc_product_rating(product_id):
    avg_rating, count_reviews = db.session.query(func.avg(Review.rating), func.count(Review.id)) \
        .filter(Review.product_id == product_id).one()
    avg_rating = float(avg_rating or 0.0)
    count_reviews = int(count_reviews or 0)

    product = Product.query.get(product_id)
    product.rating = round(avg_rating, 2)
    product.review_count = count_reviews
    db.session.commit()
@app.context_processor
def inject_globals():
    # Kampanya bannerı için ilk aktif kampanya
    campaign = Campaign.query.first()

    # Sepet sayısı
    cart_count = 0
    if current_user.is_authenticated:
        cart_count = CartItem.query.filter_by(user_id=current_user.id).count()

    # Kategoriler
    categories = Category.query.all()

    return dict(campaign=campaign, cart_count=cart_count, categories=categories)    
from flask_login import login_required, current_user
@app.route("/product/<int:pid>", methods=["GET", "POST"])
def product_detail(pid):
    product = Product.query.get_or_404(pid)

    add_to_cart_form = AddToCartForm()
    review_form = ReviewForm()

    # --- Sepete ekleme akışı ---
    if add_to_cart_form.validate_on_submit() :
        if not current_user.is_authenticated:
            flash("Sepete ürün eklemek için giriş yapmalısınız.", "danger")
            return redirect(url_for("login"))

        quantity = add_to_cart_form.quantity.data or 1

        if product.stock < quantity:
            flash("Yeterli stok yok.", "warning")
            return redirect(url_for("product_detail", pid=pid))

        # Sepet item kontrolü
        cart_item = CartItem.query.filter_by(
            user_id=current_user.id, product_id=product.id
        ).first()

        if cart_item:
            cart_item.quantity += add_to_cart_form.quantity.data
        else:
                cart_item = CartItem(
                    user_id=current_user.id,
                    product_id=product.id,
                    quantity=add_to_cart_form.quantity.data
                )
                db.session.add(cart_item)

        db.session.commit()
        flash("Ürün sepete eklendi.", "success")
        return redirect(url_for("cart"))


    # --- Yorum ekleme akışı ---
    if review_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("Yorum eklemek için giriş yapmalısınız.", "danger")
            return redirect(url_for("login"))

        existing = Review.query.filter_by(
            product_id=product.id, user_id=current_user.id
        ).first()
        if existing:
            flash("Bu ürüne zaten yorum yapmışsınız.", "warning")
            return redirect(url_for("product_detail", pid=pid))

        new_review = Review(
            product_id=product.id,
            user_id=current_user.id,
            rating=review_form.rating.data,
            comment=review_form.comment.data
        )
        db.session.add(new_review)
        db.session.commit()

        recalc_product_rating(product.id)

        flash("Yorumunuz eklendi.", "success")
        return redirect(url_for("product_detail", pid=pid))

    # --- İlgili ürünler ve yorumlar ---
    related_products = Product.query.filter(
        Product.category_id == product.category_id,
        Product.id != product.id,
        Product.is_active == True
    ).order_by(Product.sales_count.desc()).limit(4).all()

    reviews = Review.query.filter_by(
        product_id=product.id
    ).order_by(Review.created_at.desc()).all()

    return render_template(
        "product_detail.html",
        product=product,
        form=add_to_cart_form,
        review_form=review_form,
        reviews=reviews,
        related_products=related_products
    )

# --- Wishlist (DB tabanlı) ---
@app.route("/wishlist")
@login_required
def wishlist():
    items = WishlistItem.query.filter_by(user_id=current_user.id).all()
    products = [Product.query.get(i.product_id) for i in items]
    return render_template("wishlist.html", wishlist_items=products)
@app.route("/wishlist/add/<int:pid>", methods=["POST"])
@login_required
def wishlist_add(pid):
    form = WishlistForm()
    product = Product.query.get_or_404(pid)

    if form.validate_on_submit():
        existing = WishlistItem.query.filter_by(user_id=current_user.id, product_id=pid).first()
        if not existing:
            item = WishlistItem(user_id=current_user.id, product_id=pid)
            db.session.add(item)
            db.session.commit()
            flash("Ürün favorilere eklendi.", "success")
        else:
            flash("Bu ürün zaten favorilerinizde.", "info")

    return redirect(url_for("product_detail", pid=pid))
@app.route("/wishlist/remove/<int:pid>", methods=["POST"])
@login_required
def wishlist_remove(pid):
    product = Product.query.get_or_404(pid)

    item = WishlistItem.query.filter_by(user_id=current_user.id, product_id=pid).first()
    if item:
        db.session.delete(item)
        db.session.commit()
        flash("Ürün favorilerden kaldırıldı.", "success")
    else:
        flash("Bu ürün favorilerinizde bulunmuyor.", "info")

    return redirect(url_for("wishlist"))
# --- Cart ---
@app.route("/cart")
@login_required
def cart():
    cart_items_raw = CartItem.query.filter_by(user_id=current_user.id).all()

    cart_items = []
    subtotal = 0
    total_discount = 0
    shipping_total = 0

    for ci in cart_items_raw:
        product = ci.product

        # Kampanya veya ürün indirimi
        effective_discount = product.campaign.discount if product.campaign else product.discount or 0

        # İndirim uygulanmadan önceki fiyat
        original_price = product.price

        # İndirimli fiyat
        discounted_price = original_price * (1 - effective_discount / 100)

        quantity = ci.quantity
        subtotal_item = discounted_price * quantity
        shipping_cost = 0.0

        # Toplamlar
        subtotal += original_price * quantity
        total_discount += (original_price - discounted_price) * quantity
        shipping_total += shipping_cost

        cart_items.append({
            "id": ci.id,
            "name": product.name,
            "image_url": product.image_url,
            "seller": product.supplier,
            "original_price": original_price,
            "discount": effective_discount,
            "price": discounted_price,
            "quantity": quantity,
            "subtotal": subtotal_item,
            "shipping_cost": shipping_cost,
            "campaign_title": product.campaign.title if product.campaign else None
        })

    grand_total = subtotal - total_discount + shipping_total

    return render_template(
        "cart.html",
        cart_items=cart_items,
        subtotal=subtotal,
        total_discount=total_discount,
        shipping_total=shipping_total,
        grand_total=grand_total
    )


@app.route("/cart/add/<int:pid>", methods=["POST"])
@login_required
def cart_add(pid):
    product = Product.query.get_or_404(pid)
    qty = int(request.form.get("quantity", 1))

    cart_item = CartItem.query.filter_by(user_id=current_user.id, product_id=pid).first()
    if cart_item:
        cart_item.quantity += qty
    else:
        cart_item = CartItem(user_id=current_user.id, product_id=pid, quantity=qty)
        db.session.add(cart_item)

    db.session.commit()
    flash("Ürün sepete eklendi.", "success")
    return redirect(url_for("cart"))


@app.route("/cart/remove/<int:cid>")
@login_required
def cart_remove(cid):
    cart_item = CartItem.query.get_or_404(cid)
    if cart_item.user_id != current_user.id:
        flash("Bu ürünü silemezsiniz.", "danger")
        return redirect(url_for("cart"))

    db.session.delete(cart_item)
    db.session.commit()
    flash("Ürün sepetten kaldırıldı.", "info")
    return redirect(url_for("cart"))


# --- Auth ---
@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if request.method == "POST" and form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash("Hoşgeldiniz.", "success")
            return redirect(url_for("index"))
        else:
            flash("E-posta veya şifre hatalı.", "danger")
    return render_template("login.html", form=form)


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if request.method == "POST" and form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash("Bu e-posta ile zaten kayıtlı bir kullanıcı var.", "danger")
            return redirect(url_for("register"))

        user = User(
            fullname=form.fullname.data,
            email=form.email.data,
            auth_provider="local"
        )
        user.set_password(form.password.data)

        db.session.add(user)
        db.session.commit()

        login_user(user)
        flash("Kayıt başarılı, hoşgeldiniz!", "success")
        return redirect(url_for("index"))

    return render_template("register.html", form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Çıkış yapıldı.", "info")
    return redirect(url_for("index"))


# --- Profile ---
@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user = current_user
    if request.method == "POST":
        fullname = request.form.get("fullname", user.fullname)
        email = request.form.get("email", user.email)
        phone = request.form.get("phone", user.phone)

        if email != user.email and User.query.filter_by(email=email).first():
            flash("Bu e-posta zaten kullanılıyor.", "warning")
        else:
            user.fullname = fullname
            user.email = email
            user.phone = phone
            db.session.commit()
            flash("Profil güncellendi.", "success")
        return redirect(url_for("profile"))

    return render_template("profile.html", user=user)


# --- Contact ---
@app.route("/contact", methods=["GET", "POST"])
def contact():
    form = ContactForm()
    if request.method == "POST" and form.validate_on_submit():
        flash("Mesajınız başarıyla iletildi.", "success")
        return redirect(url_for("contact"))
    return render_template("contact.html", form=form)


# --- Static info pages ---
@app.route("/faq")
def faq():
    return render_template("faq.html")

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/privacy_policy")
def privacy_policy():
    return render_template("privacy_policy.html")

@app.route("/terms_of_service")
def terms_of_service():
    return render_template("terms_of_service.html")


# --- Campaigns ---
@app.route("/campaigns")
def campaigns():
    data = Campaign.query.all()
    return render_template("campaigns.html", campaigns=data)
@app.route("/admin/categories", methods=["GET", "POST"])
@admin_required
def admin_categories():
    # Düzenleme için parametre
    cid = request.args.get("edit", type=int)
    category = None

    if cid:
        category = Category.query.get_or_404(cid)
        form = CategoryForm(obj=category)
    else:
        form = CategoryForm()

    # Form submit
    if form.validate_on_submit():
        if category:  # düzenleme
            category.name = form.name.data
            category.description = form.description.data
            flash("Kategori güncellendi.", "success")
        else:  # ekleme
            new_cat = Category(
                name=form.name.data,
                description=form.description.data
            )
            db.session.add(new_cat)
            flash("Kategori başarıyla eklendi.", "success")

        db.session.commit()
        return redirect(url_for("admin_categories"))

    # Silme işlemi
    if request.method == "POST" and "delete_id" in request.form:
        del_id = int(request.form["delete_id"])
        cat_to_delete = Category.query.get_or_404(del_id)
        db.session.delete(cat_to_delete)
        db.session.commit()
        flash("Kategori silindi.", "danger")
        return redirect(url_for("admin_categories"))

    categories = Category.query.all()
    return render_template("admin_categories.html", form=form, categories=categories, edit_category=category)
@app.route("/admin/categories/edit/<int:cid>", methods=["GET", "POST"])
@admin_required
def edit_category(cid):
    category = Category.query.get_or_404(cid)
    form = CategoryForm(obj=category)
    if form.validate_on_submit():
        category.name = form.name.data
        category.description = form.description.data
        db.session.commit()
        flash("Kategori güncellendi.", "success")
        return redirect(url_for("admin_categories"))
    return render_template("admin/edit_category.html", form=form, category=category)
@app.route("/admin/categories/delete/<int:cid>", methods=["POST"])
@admin_required
def delete_category(cid):
    category = Category.query.get_or_404(cid)
    db.session.delete(category)
    db.session.commit()
    flash("Kategori silindi.", "danger")
    return redirect(url_for("admin_categories"))
@app.route("/admin/category/add", methods=["GET", "POST"])
@login_required
def admin_add_category():
    form = CategoryForm()
    if form.validate_on_submit():
        new_cat = Category(name=form.name.data, description=form.description.data)
        db.session.add(new_cat)
        db.session.commit()
        flash("Kategori başarıyla eklendi.", "success")
        return redirect(url_for("category_list"))
    return render_template("admin/category_add.html", form=form)

# Kampanya Listeleme
@app.route("/admin/campaigns")
@admin_required
def admin_campaigns():
    campaigns = Campaign.query.all()
    return render_template("admin_campaigns.html", campaigns=campaigns)
# Kampanya Ekle
@app.route("/admin/campaigns/add", methods=["GET", "POST"])
@admin_required
def admin_campaign_add():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        if not title:
            flash("Kampanya başlığı boş olamaz.", "danger")
            return redirect(url_for("admin_campaign_add"))

        discount = int(request.form.get("discount", 0))
        if discount < 0 or discount > 100:
            flash("İndirim 0 ile 100 arasında olmalı.", "danger")
            return redirect(url_for("admin_campaign_add"))

        campaign = Campaign(
            title=title,
            description=request.form.get("description", "").strip(),
            discount=discount
        )

        # Görsel yükleme
        if "image" in request.files:
            file = request.files["image"]
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                # timestamp ekleyerek benzersiz dosya adı
                filename = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{filename}"
                os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
                filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                file.save(filepath)
                campaign.image_url = f"uploads/{filename}"

        db.session.add(campaign)
        db.session.commit()
        flash("Kampanya eklendi.", "success")
        return redirect(url_for("admin_campaigns"))

    return render_template("admin_campaign_form.html")


# Kampanya Düzenle
@app.route("/admin/campaigns/edit/<int:cid>", methods=["GET", "POST"])
@admin_required
def admin_campaign_edit(cid):
    campaign = Campaign.query.get_or_404(cid)
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        if not title:
            flash("Kampanya başlığı boş olamaz.", "danger")
            return redirect(url_for("admin_campaign_edit", cid=cid))

        discount = int(request.form.get("discount", campaign.discount))
        if discount < 0 or discount > 100:
            flash("İndirim 0 ile 100 arasında olmalı.", "danger")
            return redirect(url_for("admin_campaign_edit", cid=cid))

        campaign.title = title
        campaign.description = request.form.get("description", campaign.description).strip()
        campaign.discount = discount

        # Görsel güncelleme (sadece yeni dosya yüklenirse)
        if "image" in request.files:
            file = request.files["image"]
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filename = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{filename}"
                os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
                filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                file.save(filepath)
                campaign.image_url = f"uploads/{filename}"

        db.session.commit()
        flash("Kampanya güncellendi.", "success")
        return redirect(url_for("admin_campaigns"))

    return render_template("admin_campaign_form.html", campaign=campaign)
# Kampanya Sil
@app.route("/admin/campaigns/delete/<int:cid>", methods=["POST"])
@admin_required
def admin_campaign_delete(cid):
    campaign = Campaign.query.get_or_404(cid)
    db.session.delete(campaign)
    db.session.commit()
    flash("Kampanya silindi.", "danger")
    return redirect(url_for("admin_campaigns"))

@app.route("/checkout", methods=["GET", "POST"])
@login_required
def checkout():
    # Kullanıcının sepetindeki ürünleri çek
    cart_items_raw = CartItem.query.filter_by(user_id=current_user.id).all()
    if not cart_items_raw:
        flash("Sepetiniz boş.", "info")
        return redirect(url_for("cart"))

    # Hesaplamalar
    subtotal = 0
    total_discount = 0
    shipping_total = 0.0

    for ci in cart_items_raw:
        product = ci.product

        # Kampanya varsa kampanya indirimi, yoksa ürün indirimi
        effective_discount = product.campaign.discount if product.campaign else (product.discount or 0)

        original_price = product.price
        discounted_price = original_price * (1 - effective_discount / 100)

        quantity = ci.quantity

        subtotal += original_price * quantity
        total_discount += (original_price - discounted_price) * quantity
        shipping_total += 0.0  # ileride ürün bazlı yapılabilir

    grand_total = subtotal - total_discount + shipping_total

    form = CheckoutForm()
    if form.validate_on_submit():
        # Sipariş oluştur
        order = Order(
            user_id=current_user.id,
            total_price=grand_total,
            status="Hazırlanıyor"
        )
        db.session.add(order)
        db.session.flush()  # order.id almak için

        # Sipariş ürünlerini ekle
        for ci in cart_items_raw:
            product = ci.product
            effective_discount = product.campaign.discount if product.campaign else (product.discount or 0)
            discounted_price = product.price * (1 - effective_discount / 100)

            db.session.add(OrderItem(
                order_id=order.id,
                product_id=ci.product_id,
                quantity=ci.quantity,
                unit_price=discounted_price
            ))

        db.session.commit()

        # Sepeti temizle
        CartItem.query.filter_by(user_id=current_user.id).delete()
        db.session.commit()

        flash("Siparişiniz başarıyla oluşturuldu.", "success")
        return redirect(url_for("order_confirmation", order_id=order.id))

    return render_template(
        "checkout.html",
        form=form,
        subtotal=subtotal,
        total_discount=total_discount,
        shipping_total=shipping_total,
        grand_total=grand_total
    )
# Sipariş onayı
@app.route("/order/confirmation/<int:order_id>")
@login_required
def order_confirmation(order_id):
    order = Order.query.get_or_404(order_id)
    if order.user_id != current_user.id:
        flash("Bu sipariş size ait değil.", "danger")
        return redirect(url_for("cart"))

    return render_template("order_confirmation.html", order=order)


# Sipariş geçmişi
@app.route("/order_history")
@login_required
def order_history():
    orders = (Order.query
              .filter_by(user_id=current_user.id)
              .order_by(Order.created_at.desc())
              .all())
    return render_template("order_history.html", orders=orders)


# Sipariş detay
@app.route("/order_detail/<int:order_id>")
@login_required
def order_detail(order_id):
    order = Order.query.filter_by(id=order_id, user_id=current_user.id).first_or_404()
    return render_template("order_detail.html", order=order)


# Ödeme başarısız
@app.route("/payment_fail")
def payment_fail():
    return render_template("payment_fail.html")
# --- Admin panel protected ---
@app.route("/admin", methods=["GET", "POST"])
@app.route("/admin")
@admin_required
def admin():
    stats = {
        "users": User.query.count(),
        "products": Product.query.count(),
        "orders": Order.query.count(),
        "campaigns": Campaign.query.count(),
    }

    # Sadece istatistikleri gönderiyoruz
    return render_template(
        "admin.html",
        stats=stats
    )
# --- Sipariş Listeleme ---
@app.route("/admin/orders")
@admin_required
def admin_orders():
    orders = Order.query.order_by(Order.created_at.desc()).all()
    return render_template("admin_orders.html", orders=orders)

# --- Sipariş Düzenleme ---
@app.route("/admin/orders/edit/<int:oid>", methods=["GET", "POST"])
@admin_required
def admin_order_edit(oid):
    order = Order.query.get_or_404(oid)
    if request.method == "POST":
        order.status = request.form.get("status", order.status)
        order.total_price = float(request.form.get("total_price", order.total_price))
        db.session.commit()
        flash("Sipariş güncellendi.", "success")
        return redirect(url_for("admin_orders"))
    return render_template("admin_order_form.html", order=order)
# --- Proposal PDF generation (WeasyPrint preferred, wkhtmltopdf fallback) ---
@app.route("/proposal/<int:proposal_id>/pdf")
@login_required
def proposal_pdf(proposal_id):
    proposal = Proposal.query.get_or_404(proposal_id)
    items = ProposalItem.query.filter_by(proposal_id=proposal_id).all()

    html_str = render_template("proposal_pdf.html", proposal=proposal, items=items)

    try:
        if WEASYPRINT_AVAILABLE:
            pdf = HTML(string=html_str, base_url=request.base_url).write_pdf()
            return send_file(
                io.BytesIO(pdf),
                mimetype="application/pdf",
                as_attachment=True,
                download_name=f"teklif_{proposal_id}.pdf"
            )
        else:
            wkhtml_path = "wkhtmltopdf"
            tmp_html = os.path.join(app.config["UPLOAD_FOLDER"], f"proposal_{proposal_id}.html")
            tmp_pdf = os.path.join(app.config["UPLOAD_FOLDER"], f"proposal_{proposal_id}.pdf")

            with open(tmp_html, "w", encoding="utf-8") as f:
                f.write(html_str)
            subprocess.run([wkhtml_path, tmp_html, tmp_pdf], check=True)

            with open(tmp_pdf, "rb") as f:
                pdf_bytes = f.read()

            os.remove(tmp_html)
            os.remove(tmp_pdf)

            return send_file(
                io.BytesIO(pdf_bytes),
                mimetype="application/pdf",
                as_attachment=True,
                download_name=f"teklif_{proposal_id}.pdf"
            )
    except Exception:
        flash("PDF oluşturma yapılandırılmadı. HTML çıktı gösteriliyor.", "warning")
        return html_str


from slugify import slugify

def generate_unique_slug(name):
    base_slug = slugify(name)
    slug = base_slug
    counter = 1
    while Product.query.filter_by(slug=slug).first():
        slug = f"{base_slug}-{counter}"
        counter += 1
    return slug
# --- Admin Products ---
@app.route("/admin/products")
@admin_required
def admin_products():
    products = Product.query.all()
    return render_template("admin_products.html", products=products)


# --- File Upload Config ---
app.config["UPLOAD_FOLDER"] = os.path.join(os.getcwd(), "static", "uploads")
app.config["ALLOWED_EXTENSIONS"] = {"png", "jpg", "jpeg", "gif"}

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in app.config["ALLOWED_EXTENSIONS"]

# --- Add Product ---
@app.route("/admin/products/add", methods=["GET", "POST"])
@admin_required
def admin_product_add():
    if request.method == "POST":
        campaign_id_raw = request.form.get("campaign_id")
        campaign_id = int(campaign_id_raw) if campaign_id_raw else None

        product = Product(
            name=request.form["name"],
            price=float(request.form["price"]),
            category_id=int(request.form["category_id"]),
            campaign_id=campaign_id,
            description=request.form.get("description", ""),
            stock=int(request.form.get("stock", 0)),
            sku=request.form.get("sku"),
            brand=request.form.get("brand"),
            discount=int(request.form.get("discount", 0)),
            is_active=bool(int(request.form.get("is_active", 1))),
            shipping_info=request.form.get("shipping_info"),
            weight=float(request.form.get("weight", 0)) if request.form.get("weight") else None,
            dimensions=request.form.get("dimensions"),
            warranty=request.form.get("warranty"),
            supplier=request.form.get("supplier"),
            slug=request.form.get("slug") or generate_unique_slug(request.form["name"]),
            seo_title=request.form.get("seo_title"),
            seo_description=request.form.get("seo_description"),
            tags=request.form.get("tags"),
            features=request.form.get("features"),
            variants=request.form.get("variants")
        )

        # Görsel yükleme
        if "image" in request.files:
            file = request.files["image"]
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
                filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                file.save(filepath)
                product.image_url = f"uploads/{filename}"

        db.session.add(product)
        db.session.commit()
        flash("Ürün eklendi.", "success")
        return redirect(url_for("admin_products"))

    categories = Category.query.all()
    campaigns = Campaign.query.all()
    return render_template("admin_product_form.html", categories=categories, campaigns=campaigns)


# --- Edit Product ---
@app.route("/admin/products/edit/<int:pid>", methods=["GET", "POST"])
@admin_required
def admin_product_edit(pid):
    product = Product.query.get_or_404(pid)
    if request.method == "POST":
        product.name = request.form["name"]
        product.price = float(request.form["price"])
        product.category_id = int(request.form["category_id"])
        product.description = request.form.get("description", "")
        product.stock = int(request.form.get("stock", 0))
        product.sku = request.form.get("sku", product.sku)
        product.brand = request.form.get("brand", product.brand)
        product.discount = int(request.form.get("discount", 0))
        product.is_active = bool(int(request.form.get("is_active", 1)))
        product.shipping_info = request.form.get("shipping_info", product.shipping_info)
        product.weight = float(request.form.get("weight", product.weight or 0)) if request.form.get("weight") else product.weight
        product.dimensions = request.form.get("dimensions", product.dimensions)
        product.warranty = request.form.get("warranty", product.warranty)
        product.supplier = request.form.get("supplier", product.supplier)
        product.slug = request.form.get("slug") or generate_unique_slug(request.form["name"])
        product.seo_title = request.form.get("seo_title", product.seo_title)
        product.seo_description = request.form.get("seo_description", product.seo_description)
        product.tags = request.form.get("tags", product.tags)
        product.features = request.form.get("features", product.features)
        product.variants = request.form.get("variants", product.variants)

        # Kampanya güncelleme
        campaign_id_raw = request.form.get("campaign_id")
        product.campaign_id = int(campaign_id_raw) if campaign_id_raw else None

        # Görsel güncelleme
        if "image" in request.files:
            file = request.files["image"]
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
                filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                file.save(filepath)
                product.image_url = f"uploads/{filename}"

        db.session.commit()
        flash("Ürün güncellendi.", "success")
        return redirect(url_for("admin_products"))

    categories = Category.query.all()
    campaigns = Campaign.query.all()
    return render_template("admin_product_form.html", product=product, categories=categories, campaigns=campaigns)
# --- Delete Product ---
@app.route("/admin/products/delete/<int:pid>", methods=["POST"])
@admin_required
def admin_product_delete(pid):
    product = Product.query.get_or_404(pid)
    # Gerçekten silmek yerine pasif hale getiriyoruz
    product.is_active = False
    db.session.commit()
    flash(f"Ürün '{product.name}' yayından kaldırıldı.", "warning")
    return redirect(url_for("admin_products"))
from flask import render_template, redirect, url_for, flash
from flask_login import login_required


@app.route("/admin/users")
@login_required
def admin_users():
    users = User.query.all()
    return render_template("admin_users.html", users=users)


@app.route("/admin/users/toggle/<int:uid>", methods=["POST"])
@login_required
def admin_user_toggle(uid):
    user = User.query.get_or_404(uid)
    user.is_active = not user.is_active
    db.session.commit()
    flash("Kullanıcı durumu güncellendi.", "success")
    return redirect(url_for("admin_users"))

@app.route("/admin/users/delete/<int:uid>", methods=["POST"])
@login_required
def admin_user_delete(uid):
    user = User.query.get_or_404(uid)
    db.session.delete(user)
    db.session.commit()
    flash("Kullanıcı silindi.", "danger")
    return redirect(url_for("admin_users"))
from flask import render_template
from flask_login import login_required



@app.route("/admin/users/<int:uid>")
@login_required
def admin_user_detail(uid):
    # Kullanıcıyı getir
    user = User.query.get_or_404(uid)

    # İlişkili veriler (relationship'ler modelde tanımlı olmalı)
    orders = user.orders if hasattr(user, "orders") else []
    wishlist_items = user.wishlist_items if hasattr(user, "wishlist_items") else []
    reviews = user.reviews if hasattr(user, "reviews") else []

    return render_template(
        "admin_user_detail.html",
        user=user,
        orders=orders,
        wishlist_items=wishlist_items,
        reviews=reviews
    )
# --- Error handlers ---
@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(403)
def forbidden(e):
    flash("Erişim reddedildi.", "warning")
    return redirect(url_for("index"))

# --- Run ---
if __name__ == "__main__":
    # In production: run behind WSGI (gunicorn/uwsgi), enable HTTPS, set secure cookies, etc.
    app.run(host="127.0.0.1", port=5000, debug=True)