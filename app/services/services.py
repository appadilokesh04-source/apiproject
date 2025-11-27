from sqlalchemy.orm import Session
from .. import models, schemas
from ..import schemas
from ..utils.security import get_password_hash, verify_password, create_access_token
from fastapi import HTTPException, status
from typing import Optional
from sqlalchemy import desc, asc
from app.schemas import UserCreate



import math

def create_user(db: Session, user_in: schemas.UserCreate):
    from ..import models
    existing = db.query(models.User).filter(models.User.email == user_in.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed = get_password_hash(user_in.password)
    user = models.User(email=user_in.email, hashed_password=hashed, full_name=user_in.full_name)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

def authenticate_user(db: Session, email: str, password: str):
    from ..import models
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user

def create_token_for_user(user: "models.User"):
    from ..import models
    token = create_access_token({"user_id": user.id, "is_admin": user.is_admin})
    return {"access_token": token, "token_type": "bearer"}

def list_categories(db: Session):
    from ..import models
    return db.query(models.Category).all()

def get_category(db: Session, category_id: int):
    from ..import models
    return db.query(models.Category).filter(models.Category.id == category_id).first()

def create_category(db: Session, c_in: schemas.CategoryCreate):
    from ..import models
    c = models.Category(name=c_in.name, image_url=c_in.image_url)
    db.add(c)
    db.commit()
    db.refresh(c)
    return c

def create_product(db: Session, p_in: schemas.ProductCreate):
    from ..import models
    product = models.Product(
        name=p_in.name,
        description=p_in.description,
        category_id=p_in.category_id,
        price=p_in.price,
        discount=p_in.discount or 0.0,
        stock=p_in.stock or 0,
        rating=p_in.rating or 0.0,
        metal_type=p_in.metal_type,
        polish_type=p_in.polish_type,
        image_url=p_in.image_url
    )
    db.add(product)
    db.commit()
    db.refresh(product)
    return product

def update_product(db: Session, product_id: int, p_in: dict):
    from ..import models
    product = db.query(models.Product).filter(models.Product.id == product_id).first()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    for k, v in p_in.items():
        if hasattr(product, k):
            setattr(product, k, v)
    db.commit()
    db.refresh(product)
    return product

def delete_product(db: Session, product_id: int):
    from ..import models
    product = db.query(models.Product).filter(models.Product.id == product_id).first()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    db.delete(product)
    db.commit()
    return True

def get_product(db: Session, product_id: int):
    from ..import models
    return db.query(models.Product).filter(models.Product.id == product_id).first()

def list_products(db: Session, page: int =1, limit: int =10, price_min: Optional[float]=None, price_max: Optional[float]=None, metal: Optional[str]=None, polish: Optional[str]=None, sort: Optional[str]=None):
    from ..import models
    q = db.query(models.Product)
    if price_min is not None:
        q = q.filter(models.Product.price >= price_min)
    if price_max is not None:
        q = q.filter(models.Product.price <= price_max)
    if metal:
        q = q.filter(models.Product.metal_type.ilike(f"%{metal}%"))
    if polish:
        q = q.filter(models.Product.polish_type.ilike(f"%{polish}%"))
    if sort == "latest":
        q = q.order_by(desc(models.Product.created_at))
    elif sort == "price_low":
        q = q.order_by(asc(models.Product.price))
    elif sort == "price_high":
        q = q.order_by(desc(models.Product.price))
    elif sort == "rating":
        q = q.order_by(desc(models.Product.rating))
    elif sort == "popularity":
        q = q.order_by(desc(models.Product.rating))
    else:
        q = q.order_by(desc(models.Product.created_at))
    total = q.count()
    page = max(1, page)
    limit = max(1, min(100, limit))
    items = q.offset((page - 1) * limit).limit(limit).all()
    return {"items": items, "total": total, "page": page, "limit": limit, "pages": math.ceil(total / limit) if limit else 0}

def create_order(db: Session, user_id: int, order_in: schemas.OrderCreate):
    from ..import models
    total = 0.0
    items_models = []
    for item in order_in.items:
        product = db.query(models.Product).filter(models.Product.id == item.product_id).with_for_update().first()
        if not product:
            raise HTTPException(status_code=404, detail=f"Product {item.product_id} not found")
        if product.stock < item.quantity:
            raise HTTPException(status_code=400, detail=f"Not enough stock for product {product.id}")
        unit_price = product.price - (product.discount or 0.0)
        total += unit_price * item.quantity
        product.stock -= item.quantity
        items_models.append(models.OrderItem(product_id=product.id, quantity=item.quantity, unit_price=unit_price))
    order = models.Order(user_id=user_id, total_price=total, payment_status="pending", address=order_in.address)
    db.add(order)
    db.flush()
    for im in items_models:
        im.order_id = order.id
        db.add(im)
    db.commit()
    db.refresh(order)
    return order

def get_orders_for_user(db: Session, user_id: int):
    from ..import models
    return db.query(models.Order).filter(models.Order.user_id == user_id).all()

def get_order(db: Session, user_id: int, order_id: int):
    from ..import models
    order = db.query(models.Order).filter(models.Order.id == order_id).first()
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    if order.user_id != user_id:
        raise HTTPException(status_code=403, detail="Not authorized")
    return order
