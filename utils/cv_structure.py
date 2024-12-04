from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class Contact(BaseModel):
    email: str = ""
    phone: str = ""
    location: str = ""

class Experience(BaseModel):
    title: str = ""
    company: str = ""
    date: str = ""
    description: str = ""

class Education(BaseModel):
    degree: str = ""
    institution: str = ""
    date: str = ""

class CV(BaseModel):
    name: str = ""
    title: str = ""
    contact: Contact = Field(default_factory=Contact)
    profile_picture: str = ""
    summary: str = ""
    skills: List[str] = Field(default_factory=list)
    experience: List[Experience] = Field(default_factory=list)
    education: List[Education] = Field(default_factory=list)
    languages: List[str] = Field(default_factory=list)
    hourly_rate: str = ""
    portfolio: List[str] = Field(default_factory=list)
    certifications: str = ""
    testimonials: List[str] = Field(default_factory=list)

    class Config:
        extra = "allow"
