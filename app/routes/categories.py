from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from ..config.database import SessionLocal
from ..services import services
from ..schemas import schemas
from ..routes.users import admin_required

router = APIRouter(prefix="/api/categories", tags=["categories"])

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.get("", response_model=list[schemas.CategoryOut])
def list_categories(db: Session = Depends(get_db)):
    return services.list_categories(db)

#@router.post("", response_model=schemas.CategoryOut)
#def create_category(c_in: schemas.CategoryCreate, db: Session = Depends(get_db)):
 #   return services.create_category(db, c_in)
@router.post("", response_model=schemas.CategoryOut, dependencies=[Depends(admin_required)]) # <-- ADDED ADMIN DEPENDENCY
def create_category(c_in: schemas.CategoryCreate, db: Session = Depends(get_db)):
    return services.create_category(db, c_in)

@router.get("/{category_id}/products", response_model=list[schemas.ProductOut])
def get_category_products(category_id: int, db: Session = Depends(get_db)):
    c = services.get_category(db, category_id)
    if not c:
        raise HTTPException(status_code=404, detail="Category not found")
    return c.products
