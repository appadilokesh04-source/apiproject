from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from ..config.database import SessionLocal
from ..schemas import schemas
from ..services import services
from ..routes.users import _get_current_user

router = APIRouter(prefix="/api/orders", tags=["orders"])

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.post("", response_model=schemas.OrderOut)
def create_order(order_in: schemas.OrderCreate, db: Session = Depends(get_db), current_user = Depends(_get_current_user)):
    order = services.create_order(db, current_user.id, order_in)
    return order

@router.get("", response_model=list[schemas.OrderOut])
def list_orders(db: Session = Depends(get_db), current_user = Depends(_get_current_user)):
    orders = services.get_orders_for_user(db, current_user.id)
    return orders

@router.get("/{order_id}", response_model=schemas.OrderOut)
def get_order(order_id: int, db: Session = Depends(get_db), current_user = Depends(_get_current_user)):
    return services.get_order(db, current_user.id, order_id)
