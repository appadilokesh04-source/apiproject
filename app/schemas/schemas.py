from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List
from datetime import datetime

class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=6)
    full_name: Optional[str]

class UserOut(BaseModel):
    id: int
    email: EmailStr
    full_name: Optional[str]
    is_admin: bool
    created_at: datetime
    class Config:
        orm_mode = True

class Token(BaseModel):
    access_token: str
    token_type: str

class CategoryCreate(BaseModel):
    name: str
    image_url: Optional[str]

class CategoryOut(BaseModel):
    id: int
    name: str
    image_url: Optional[str]
    class Config:
        orm_mode = True

class ProductCreate(BaseModel):
    name: str
    description: Optional[str]
    category_id: Optional[int]
    price: float
    discount: Optional[float] = 0.0
    stock: Optional[int] = 0
    rating: Optional[float] = 0.0
    metal_type: Optional[str]
    polish_type: Optional[str]
    image_url: Optional[str]

class ProductOut(BaseModel):
    id: int
    name: str
    description: Optional[str]
    category: Optional[CategoryOut]
    price: float
    discount: float
    stock: int
    rating: float
    metal_type: Optional[str]
    polish_type: Optional[str]
    image_url: Optional[str]
    created_at: Optional[datetime]
    updated_at: Optional[datetime]
    class Config:
        orm_mode = True

class OrderItemIn(BaseModel):
    product_id: int
    quantity: int = Field(gt=0)

class OrderCreate(BaseModel):
    items: List[OrderItemIn]
    address: Optional[str]

class OrderItemOut(BaseModel):
    id: int
    product_id: int
    quantity: int
    unit_price: float
    class Config:
        orm_mode = True

class OrderOut(BaseModel):
    id: int
    user_id: int
    total_price: float
    payment_status: str
    address: Optional[str]
    created_at: datetime
    items: List[OrderItemOut]
    class Config:
        orm_mode = True
