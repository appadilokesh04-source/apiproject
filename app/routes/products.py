from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from ..config.database import SessionLocal
from ..schemas import schemas
from ..services import services
from ..routes.users import _get_current_user, admin_required

router = APIRouter(prefix="/api/products", tags=["products"])

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.get("", response_model=dict)
def list_products(
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
    price_min: float | None = Query(None, ge=0),
    price_max: float | None = Query(None, ge=0),
    metal: str | None = None,
    polish: str | None = None,
    sort: str | None = Query(None, regex="^(latest|price_low|price_high|rating|popularity)$"),
    db: Session = Depends(get_db)
):
    result = services.list_products(db, page=page, limit=limit, price_min=price_min, price_max=price_max, metal=metal, polish=polish, sort=sort)
    return {
        "items": [schemas.ProductOut.from_orm(p) for p in result["items"]],
        "total": result["total"],
        "page": result["page"],
        "limit": result["limit"],
        "pages": result["pages"]
    }

@router.get("/{product_id}", response_model=schemas.ProductOut)
def get_product(product_id: int, db: Session = Depends(get_db)):
    p = services.get_product(db, product_id)
    if not p:
        raise HTTPException(status_code=404, detail="Product not found")
    return p

@router.post("", response_model=schemas.ProductOut, dependencies=[Depends(admin_required)])
def create_product(p_in: schemas.ProductCreate, db: Session = Depends(get_db)):
    return services.create_product(db, p_in)

@router.put("/{product_id}", response_model=schemas.ProductOut, dependencies=[Depends(admin_required)])
def update_product(product_id: int, p_in: schemas.ProductCreate, db: Session = Depends(get_db)):
    return services.update_product(db, product_id, p_in.dict(exclude_unset=True))

@router.delete("/{product_id}", dependencies=[Depends(admin_required)])
def delete_product(product_id: int, db: Session = Depends(get_db)):
    services.delete_product(db, product_id)
    return {"detail": "Deleted"}
