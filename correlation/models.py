from pydantic import BaseModel


class Entity(BaseModel):
    type: str          # "domain", "ip", "asn", "hash"
    value: str
    risk: int = 0      # 0-100
    details: dict = {}


class Relationship(BaseModel):
    source: str
    relation: str      # "resolves_to", "belongs_to", ...
    target: str


class RelatedCase(BaseModel):
    case_id: str
    shared: str                  # the strongest shared item
    confidence: float
    all_shared: list[str] = []   # every shared item (new)


class CorrelatedThreatData(BaseModel):
    case_id: str
    entities: list[Entity] = []
    relationships: list[Relationship] = []
    related_cases: list[RelatedCase] = []