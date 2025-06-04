from fastapi import APIRouter, Depends
from sqlmodel import Session, select
from app.db.database import get_session
from app.models.user import User

router = APIRouter()

@router.post("/test/", response_model=User)
def create_test_entry(entry: User, session: Session = Depends(get_session)):
    session.add(entry)
    session.commit()
    session.refresh(entry)
    return entry

@router.get("/test/", response_model=list[User])
def read_test_entries(session: Session = Depends(get_session)):
    return session.exec(select(User)).all()
