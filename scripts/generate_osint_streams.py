"""
generate_osint_streams.py — OSINT Behavioral Data Augmentation Generator.

Generates 5 synthetic OSINT Bronze streams that augment the existing 12
internal enterprise tables. All streams link back to employee_id via the
existing Social Identity (social_handle_map) table.

Streams:
  1. Twitter/X          -> bronze/osint/raw_tweets.csv
  2. Instagram          -> bronze/osint/raw_instagram_posts.csv
  3. Lifestyle Signals  -> bronze/osint/raw_lifestyle_signals.csv
  4. Financial Stress   -> bronze/osint/raw_financial_stress.csv
  5. Dark Web           -> bronze/osint/raw_darkweb_signals.csv

Behavioral realism (lead/lag timeline for threat actors, 90-day window):
  Days 01-20: Lifestyle incongruity signals (spending up)
  Days 15-35: Financial stress proxy records emerge
  Days 25-50: Twitter sentiment begins declining
  Days 40-60: Instagram sensitive location visits
  Days 55-75: Dark web signals correlate
  Days 60-90: Internal behavioral signals spike (handled by s1)
  Days 75-90: Gold composite crosses CRITICAL threshold

Usage:
    python generate_osint_streams.py [--dry-run] [--env local]
    # or called from s1_generate_raw.run()
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import random
import sys
import time
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import numpy as np
import pandas as pd
from faker import Faker

# ---------------------------------------------------------------------------
# Config (mirrors s1_generate_raw.py constants)
# ---------------------------------------------------------------------------

RANDOM_SEED    = int(os.getenv("RANDOM_SEED",    42))
EMPLOYEE_COUNT = int(os.getenv("EMPLOYEE_COUNT", 500))
TIMELINE_DAYS  = int(os.getenv("TIMELINE_DAYS",  90))
TIMELINE_START = date.fromisoformat(os.getenv("TIMELINE_START_DATE", "2026-01-01"))
HIGH_RISK_N    = 25   # must match s1_generate_raw.HIGH_RISK_N

BRONZE_DIR = Path(__file__).resolve().parent.parent / "data" / "bronze" / "osint"

# MinIO upload path — uploaded under bronze/osint/ prefix
MINIO_OSINT_PREFIX = "bronze/osint"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("generate_osint_streams")

fake = Faker()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _seed_all(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    Faker.seed(seed)


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _timeline_dates() -> list[date]:
    return [TIMELINE_START + timedelta(days=i) for i in range(TIMELINE_DAYS)]


def _threat_actor_ids() -> set[int]:
    """Reproduce the exact same high-risk cohort as s1_generate_raw.py."""
    rng = np.random.default_rng(RANDOM_SEED)
    return set(rng.choice(EMPLOYEE_COUNT, size=HIGH_RISK_N, replace=False).tolist())


def _employee_id(idx: int) -> str:
    return f"EMP_{idx + 1:05d}"


def _row_hash(row_dict: dict) -> str:
    content = json.dumps(row_dict, sort_keys=True, default=str)
    return hashlib.sha256(content.encode()).hexdigest()


def _write_csv(df: pd.DataFrame, path: Path, dry_run: bool) -> str:
    if dry_run:
        logger.info("[DRY-RUN] Would write %d rows to %s", len(df), path)
        return str(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(path, index=False)
    logger.info("Wrote %d rows -> %s", len(df), path)
    return str(path)


def _scraped_ts(day: date, rng: np.random.Generator) -> str:
    """Random timestamp within the given day (UTC)."""
    hour = int(rng.integers(0, 24))
    minute = int(rng.integers(0, 60))
    dt = datetime(day.year, day.month, day.day, hour, minute, tzinfo=timezone.utc)
    return dt.isoformat()


# ---------------------------------------------------------------------------
# Load social handle map (written by s1_generate_raw) to get handle -> employee
# ---------------------------------------------------------------------------

def _load_social_handles(dry_run: bool) -> pd.DataFrame:
    """Read the social_handle_map.csv written by s1. Falls back to synthetic if missing."""
    path = Path(__file__).resolve().parent.parent / "data" / "bronze" / "social_handle_map.csv"
    if path.exists():
        df = pd.read_csv(path)
        logger.info("Loaded %d social handles from %s", len(df), path)
        return df
    logger.warning("social_handle_map.csv not found — generating placeholder handles")
    # Generate minimal handles so generator can run standalone
    rng = np.random.default_rng(RANDOM_SEED + 200)
    rows = []
    platforms = ["twitter", "instagram", "linkedin"]
    for i in range(EMPLOYEE_COUNT):
        for platform in platforms:
            handle = f"user_{i+1:05d}_{platform[:2]}"
            rows.append({"social_handle": handle, "employee_id": _employee_id(i), "platform": platform})
    # Add ~5% unmapped
    ghost_count = int(EMPLOYEE_COUNT * 0.05)
    for g in range(ghost_count):
        platform = platforms[rng.integers(0, len(platforms))]
        rows.append({"social_handle": f"ghost_{g:04d}", "employee_id": None, "platform": platform})
    return pd.DataFrame(rows)


def _load_hris(dry_run: bool) -> pd.DataFrame:
    """Read hris_events.csv to get employee names and salary bands."""
    path = Path(__file__).resolve().parent.parent / "data" / "bronze" / "hris_events.csv"
    if path.exists():
        return pd.read_csv(path)
    # Minimal fallback
    rows = [{"employee_id": _employee_id(i), "full_name": fake.name(),
             "role_title": "Analyst", "department": "IT"} for i in range(EMPLOYEE_COUNT)]
    return pd.DataFrame(rows)


def _salary_band(role_title: str) -> str:
    title_lower = str(role_title).lower()
    if any(w in title_lower for w in ["senior", "lead", "principal", "director", "manager", "vp", "chief"]):
        return "senior"
    if any(w in title_lower for w in ["analyst", "engineer", "specialist", "associate"]):
        return "mid"
    return "low"


# ---------------------------------------------------------------------------
# Stream 1: Twitter/X
# ---------------------------------------------------------------------------

# Sentiment scoring helpers
_NEGATIVE_KEYWORDS = [
    "quit", "revenge", "money", "unfair", "opportunity", "frustrated",
    "underpaid", "overlooked", "done with", "leaving", "can't take",
    "fed up", "angry", "betrayed", "owe me", "deserve better",
]

_POSITIVE_KEYWORDS = ["great", "grateful", "excited", "love", "amazing", "blessed", "proud"]

_EMOTION_TAGS = {
    "anger": ["angry", "furious", "rant", "fed up", "outraged", "revenge"],
    "anxiety": ["stressed", "worried", "overwhelmed", "can't sleep", "pressure"],
    "frustration": ["frustrated", "unfair", "overlooked", "underpaid", "quit"],
    "financial": ["money", "bills", "debt", "mortgage", "loan", "afford", "broke"],
    "neutral": ["weather", "coffee", "weekend", "lunch", "meeting"],
    "positive": ["great", "grateful", "excited", "love", "happy", "proud"],
}


def _tweet_text(is_high_risk: bool, day_num: int, rng: np.random.Generator) -> tuple[str, float, list[str], list[str]]:
    """
    Generate tweet text + sentiment_score + emotion_tags + keyword_flags.
    Threat actors: benign early, gradually declining, critical in final 30 days.
    """
    # Threat actor phase (lead/lag: sentiment decline Days 25-90)
    if is_high_risk and day_num >= 25:
        severity = min(1.0, (day_num - 25) / 65.0)  # 0->1 over days 25-90
        if severity > 0.7:
            # Critical phase
            templates = [
                "I have given everything to this place and what do I get? Nothing. The {thing} never changes.",
                "Been thinking a lot about {topic}. Some people just don't get what they deserve.",
                "Money problems are real. Wish there were other {options}.",
                "Not sure how much longer I can keep doing this. The {thing} is just not worth it anymore.",
                "People take advantage of loyalty. Time to think about my own {opportunity}.",
                "Hearing about opportunities elsewhere. Maybe it's time to explore {options}.",
                "Why do I even bother? The {thing} is clearly rigged.",
            ]
            text = rng.choice(templates).format(
                thing=rng.choice(["system", "management", "culture", "situation"]),
                topic=rng.choice(["fairness", "loyalty", "financial reality", "opportunity"]),
                options=rng.choice(["options", "opportunities", "paths forward"]),
                opportunity=rng.choice(["future", "interests", "options"]),
            )
            sentiment = float(rng.uniform(-0.9, -0.4))
            emotions = ["frustration", "financial", "anger"]
            flags = [k for k in _NEGATIVE_KEYWORDS if k in text.lower()]
        elif severity > 0.3:
            # Declining phase
            templates = [
                "Another long week. Grateful for the weekend but honestly {feeling}.",
                "Had a tough {meeting} today. Trying to stay positive but it's hard.",
                "Thinking about {topic} more than usual lately.",
                "Sometimes I wonder if the {thing} is even worth it.",
                "Bills adding up. Hoping things turn around soon.",
            ]
            text = rng.choice(templates).format(
                feeling=rng.choice(["tired", "drained", "questioning things", "not sure"]),
                meeting=rng.choice(["conversation", "review", "discussion"]),
                topic=rng.choice(["work-life balance", "the future", "priorities"]),
                thing=rng.choice(["grind", "effort", "daily routine", "commute"]),
            )
            sentiment = float(rng.uniform(-0.4, 0.0))
            emotions = ["frustration", "anxiety"]
            flags = [k for k in _NEGATIVE_KEYWORDS if k in text.lower()]
        else:
            # Early — slightly negative but subtle
            templates = [
                "Busy week but keeping it together. {comment}",
                "Weekend can't come soon enough. {comment}",
                "Trying to stay focused. {comment}",
            ]
            text = rng.choice(templates).format(
                comment=rng.choice(["Hope things improve.", "Taking it one day at a time.", "Coffee is helping."])
            )
            sentiment = float(rng.uniform(-0.1, 0.2))
            emotions = ["neutral"]
            flags = []
    else:
        # Benign employee or early threat actor days — mundane content
        templates = [
            "Great {meal} today! {comment}",
            "Finally finished {task}. Feeling accomplished.",
            "Weekend plans: {plan}. Can't wait!",
            "Loving this {weather} weather. Perfect for {activity}.",
            "Congrats to my team on {achievement}!",
            "Coffee and {activity} — perfect morning.",
            "Happy {day}! Hope everyone has a great one.",
        ]
        text = rng.choice(templates).format(
            meal=rng.choice(["lunch", "dinner", "breakfast"]),
            comment=rng.choice(["Highly recommend!", "10/10.", "Worth it."]),
            task=rng.choice(["the project", "my report", "the presentation", "a long task"]),
            plan=rng.choice(["hiking", "reading", "family time", "catching up with friends"]),
            weather=rng.choice(["sunny", "cool", "fall", "spring"]),
            activity=rng.choice(["a walk", "running", "gardening", "reading"]),
            achievement=rng.choice(["a great quarter", "the launch", "hitting targets"]),
            day=rng.choice(["Friday", "Monday", "Wednesday"]),
        )
        sentiment = float(rng.uniform(0.2, 0.9))
        emotions = ["positive", "neutral"]
        flags = [k for k in _POSITIVE_KEYWORDS if k in text.lower()]

    # Cap at 280 chars
    text = text[:280]
    return text, sentiment, emotions, flags


def generate_twitter(handles_df: pd.DataFrame, threat_ids: set[int], dry_run: bool) -> str:
    """Generate raw_tweets.csv."""
    rng = np.random.default_rng(RANDOM_SEED + 100)
    dates = _timeline_dates()

    twitter_handles = handles_df[handles_df["platform"] == "twitter"].copy()
    records = []
    tweet_seq = 1

    for _, row in twitter_handles.iterrows():
        emp_id = row["employee_id"]
        if pd.isna(emp_id):
            continue  # skip ghost handles for tweets
        emp_idx = int(emp_id.replace("EMP_", "")) - 1
        is_high_risk = emp_idx in threat_ids
        handle = row["social_handle"]

        # Tweet frequency: threat actors tweet more as sentiment declines
        for day_num, day in enumerate(dates):
            # Base: 40% chance of tweeting any given day
            base_prob = 0.4
            if is_high_risk and day_num >= 40:
                base_prob = 0.65  # more active as frustration builds
            if rng.random() > base_prob:
                continue

            n_tweets = int(rng.integers(1, 4 if is_high_risk and day_num >= 50 else 2))
            for _ in range(n_tweets):
                tweet_id = f"TWE_{tweet_seq:05d}"
                tweet_seq += 1
                text, sentiment, emotions, flags = _tweet_text(is_high_risk, day_num, rng)
                raw = {
                    "tweet_id": tweet_id, "handle": handle,
                    "tweet_text": text, "sentiment_score": round(sentiment, 4),
                    "retweet_flag": bool(rng.random() < 0.2),
                    "like_count": int(rng.integers(0, 50)),
                }
                records.append({
                    "tweet_id":         tweet_id,
                    "scraped_datetime":  _scraped_ts(day, rng),
                    "handle":            handle,
                    "tweet_text":        text,
                    "retweet_flag":      bool(rng.random() < 0.2),
                    "like_count":        int(rng.integers(0, 50)),
                    "raw_json":          json.dumps(raw),
                })

    df = pd.DataFrame(records)
    logger.info("Twitter: %d tweets for %d employees", len(df), twitter_handles["employee_id"].notna().sum())
    return _write_csv(df, BRONZE_DIR / "raw_tweets.csv", dry_run)


# ---------------------------------------------------------------------------
# Stream 2: Instagram / Location
# ---------------------------------------------------------------------------

# DC metro area bounding box for realistic coords
_DC_LAT = (38.80, 39.00)
_DC_LON = (-77.20, -76.90)

_SENSITIVE_KEYWORDS = [
    "embassy", "consulate", "pentagon", "capitol", "nsa", "cia", "fbi",
    "defense", "dod", "langley", "fort meade", "competitor", "rivals hq",
]

_LOCATION_TEMPLATES = {
    "home_area": [
        "Bethesda, MD", "Silver Spring, MD", "Arlington, VA",
        "Alexandria, VA", "Rockville, MD", "Fairfax, VA",
    ],
    "office_area": [
        "Downtown DC", "Crystal City, VA", "Rosslyn, VA",
        "Tysons Corner, VA", "Reston, VA",
    ],
    "domestic_leisure": [
        "The Capital Grille, Washington DC", "Founding Farmers, DC",
        "Nationals Park, DC", "Kennedy Center, DC", "Georgetown Waterfront",
        "Bethesda Row", "Del Ray, Alexandria VA",
    ],
    "international": [
        "Heathrow Airport, London", "CDG Airport, Paris",
        "Frankfurt Airport, Germany", "Zurich, Switzerland",
    ],
    "sensitive_area": [
        "Embassy Row, Washington DC", "Pentagon City, VA",
        "NSA Campus, Fort Meade MD", "CIA Headquarters, Langley VA",
        "Capitol Hill, Washington DC", "Defense Intelligence Agency, DC",
    ],
}


def generate_instagram(handles_df: pd.DataFrame, threat_ids: set[int], dry_run: bool) -> str:
    """Generate raw_instagram_posts.csv."""
    rng = np.random.default_rng(RANDOM_SEED + 200)
    dates = _timeline_dates()

    ig_handles = handles_df[handles_df["platform"] == "instagram"].copy()
    records = []
    post_seq = 1

    for _, row in ig_handles.iterrows():
        emp_id = row["employee_id"]
        if pd.isna(emp_id):
            continue
        emp_idx = int(emp_id.replace("EMP_", "")) - 1
        is_high_risk = emp_idx in threat_ids
        handle = row["social_handle"]

        for day_num, day in enumerate(dates):
            # Instagram: less frequent than Twitter, ~25% daily
            post_prob = 0.25
            if is_high_risk and 40 <= day_num <= 60:
                post_prob = 0.50  # location signals cluster in this window
            if rng.random() > post_prob:
                continue

            post_id = f"IGP_{post_seq:05d}"
            post_seq += 1

            # Location type selection
            if is_high_risk and 40 <= day_num <= 60 and rng.random() < 0.35:
                loc_type = "sensitive_area"
            elif is_high_risk and day_num >= 50 and rng.random() < 0.15:
                loc_type = "international"
            elif rng.random() < 0.4:
                loc_type = "domestic_leisure"
            elif rng.random() < 0.3:
                loc_type = "office_area"
            else:
                loc_type = "home_area"

            location_string = str(rng.choice(_LOCATION_TEMPLATES[loc_type]))

            # Luxury incongruity: leisure locations with premium references
            if loc_type == "domestic_leisure" and is_high_risk and day_num <= 35:
                location_string = str(rng.choice([
                    "The Inn at Little Washington, VA",
                    "Minibar by Jose Andres, DC",
                    "The Hay-Adams, DC",
                    "Four Seasons Georgetown, DC",
                ]))

            caption_templates = {
                "home_area":        ["Quiet evening in {}. ", "Great neighborhood! {}.", "Home sweet home. {}"],
                "office_area":      ["Long day in {}. ", "Another day at {}. ", "Working from {}."],
                "domestic_leisure": ["Amazing time at {}! ", "Great dinner at {}.", "Love this place — {}!"],
                "international":    ["Traveling through {}. ", "Layover in {}. ", "Quick trip to {}."],
                "sensitive_area":   ["Interesting visit to {}. ", "Near {} today. ", "Walking around {}."],
            }
            caption = str(rng.choice(caption_templates[loc_type])).format(location_string)
            caption += str(rng.choice(["#dc #weekend", "#work #grind", "#travel #explore", "#food #yum", ""]))

            lat = float(rng.uniform(*_DC_LAT))
            lon = float(rng.uniform(*_DC_LON))

            raw = {"post_id": post_id, "handle": handle, "location": location_string,
                   "lat": lat, "lon": lon, "caption": caption}

            records.append({
                "post_id":          post_id,
                "scraped_datetime": _scraped_ts(day, rng),
                "handle":           handle,
                "post_caption":     caption[:500],
                "location_string":  location_string,
                "location_lat":     round(lat, 6),
                "location_lon":     round(lon, 6),
                "post_type":        str(rng.choice(["photo", "story", "reel"], p=[0.6, 0.3, 0.1])),
                "raw_json":         json.dumps(raw),
            })

    df = pd.DataFrame(records)
    logger.info("Instagram: %d posts", len(df))
    return _write_csv(df, BRONZE_DIR / "raw_instagram_posts.csv", dry_run)


# ---------------------------------------------------------------------------
# Stream 3: Lifestyle / Luxury Signals
# ---------------------------------------------------------------------------

_LIFESTYLE_TEMPLATES = {
    "luxury_purchase": [
        "New listing: {name} purchases {item}, estimated value ${value:,}",
        "Social post: Just picked up a {item}! Feeling great.",
        "Public record: {name} — {item} acquisition, ${value:,}",
    ],
    "property_upgrade": [
        "Property record: {name} — new residence, {address}, estimated ${value:,}",
        "Social post: New home day! Moving to {address}.",
        "Public filing: Real estate transaction, {name}, ${value:,}",
    ],
    "vehicle_upgrade": [
        "Vehicle registration: {name} — {year} {make} {model}, {county} MD/VA",
        "Social post: New ride! {year} {make} {model}. Loving it.",
        "Public record: {name} vehicle registration — {year} {make} {model}",
    ],
    "travel_upgrade": [
        "Social post: Business class to {destination}! Living my best life.",
        "Instagram caption: First class lounge at {airport}. Treating myself.",
        "Public record: Travel expense — {destination}, business class, ${value:,}",
    ],
    "fine_dining": [
        "Social post: Dinner at {restaurant}. ${value:,} well spent.",
        "Instagram check-in: {restaurant}, DC. Best meal ever.",
        "Receipt record: {restaurant} — party of {n}, ${value:,}",
    ],
}

_VEHICLES = [
    ("Mercedes", "GLE 450", 70000),
    ("BMW", "X5", 65000),
    ("Audi", "Q7", 72000),
    ("Porsche", "Cayenne", 95000),
    ("Tesla", "Model S", 80000),
    ("Land Rover", "Range Rover", 105000),
]

_RESTAURANTS = [
    "The Inn at Little Washington", "Minibar by Jose Andres",
    "Rasika West End", "Blue Duck Tavern", "The Capital Grille",
    "Fiola Mare", "Bourbon Steak", "Joe's Seafood",
]


def generate_lifestyle(handles_df: pd.DataFrame, hris_df: pd.DataFrame,
                       threat_ids: set[int], dry_run: bool) -> str:
    """Generate raw_lifestyle_signals.csv."""
    rng = np.random.default_rng(RANDOM_SEED + 300)
    dates = _timeline_dates()

    # Build handle -> employee map (any platform)
    handle_to_emp = handles_df.dropna(subset=["employee_id"]).set_index("social_handle")["employee_id"].to_dict()
    emp_to_role = {}
    if "role_title" in hris_df.columns:
        emp_to_role = hris_df.set_index("employee_id")["role_title"].to_dict()

    # Get one handle per employee (prefer instagram)
    emp_handles: dict[str, str] = {}
    for _, row in handles_df.dropna(subset=["employee_id"]).iterrows():
        eid = row["employee_id"]
        if eid not in emp_handles or row["platform"] == "instagram":
            emp_handles[eid] = row["social_handle"]

    records = []
    sig_seq = 1

    for i in range(EMPLOYEE_COUNT):
        emp_id = _employee_id(i)
        is_high_risk = i in threat_ids
        handle = emp_handles.get(emp_id, f"user_{i+1:05d}_ig")
        role = emp_to_role.get(emp_id, "Analyst")
        band = _salary_band(role)

        # Benign: rare lifestyle signals (~5% of days, low value)
        # Threat actors: signals cluster Days 1-35, higher value
        for day_num, day in enumerate(dates):
            if is_high_risk and day_num <= 35:
                signal_prob = 0.15  # spending up in early window
            elif is_high_risk:
                signal_prob = 0.05
            else:
                signal_prob = 0.03  # benign: occasional noise

            if rng.random() > signal_prob:
                continue

            sig_type = str(rng.choice(
                ["luxury_purchase", "property_upgrade", "vehicle_upgrade", "travel_upgrade", "fine_dining"],
                p=[0.25, 0.10, 0.20, 0.20, 0.25] if is_high_risk and day_num <= 35
                  else [0.15, 0.05, 0.10, 0.20, 0.50]
            ))

            name = hris_df[hris_df["employee_id"] == emp_id]["full_name"].values
            name_str = str(name[0]) if len(name) > 0 else fake.name()
            signal_id = f"LSG_{sig_seq:05d}"
            sig_seq += 1

            # Value ranges by signal type and threat status
            if sig_type == "luxury_purchase":
                value = int(rng.integers(5000, 45000) if is_high_risk else rng.integers(500, 2000))
                item = str(rng.choice(["Rolex watch", "Louis Vuitton bag", "designer suit",
                                       "luxury watch", "Hermes bag", "diamond jewelry"]))
                template = str(rng.choice(_LIFESTYLE_TEMPLATES["luxury_purchase"]))
                raw_text = template.format(name=name_str, item=item, value=value)
                source = str(rng.choice(["instagram_post", "public_notice"]))
            elif sig_type == "vehicle_upgrade":
                make, model, base_val = _VEHICLES[rng.integers(0, len(_VEHICLES))]
                value = int(base_val + rng.integers(-5000, 15000))
                year = int(rng.integers(2022, 2026))
                county = str(rng.choice(["Montgomery County", "Fairfax County", "Arlington County"]))
                template = str(rng.choice(_LIFESTYLE_TEMPLATES["vehicle_upgrade"]))
                raw_text = template.format(name=name_str, year=year, make=make, model=model, county=county)
                source = "vehicle_registration"
            elif sig_type == "property_upgrade":
                value = int(rng.integers(450000, 900000) if is_high_risk else rng.integers(200000, 350000))
                address = f"{rng.integers(100,9999)} {fake.street_name()}, {rng.choice(['Bethesda', 'McLean', 'Arlington'])} MD/VA"
                template = str(rng.choice(_LIFESTYLE_TEMPLATES["property_upgrade"]))
                raw_text = template.format(name=name_str, address=address, value=value)
                source = "property_record"
            elif sig_type == "travel_upgrade":
                value = int(rng.integers(800, 8000) if is_high_risk else rng.integers(300, 1200))
                dest = str(rng.choice(["London", "Paris", "Zurich", "Dubai", "Singapore", "Tokyo"]))
                airport = str(rng.choice(["Dulles IAD", "Reagan DCA", "BWI"]))
                template = str(rng.choice(_LIFESTYLE_TEMPLATES["travel_upgrade"]))
                raw_text = template.format(destination=dest, airport=airport, value=value)
                source = "instagram_post"
            else:  # fine_dining
                value = int(rng.integers(150, 800) if is_high_risk else rng.integers(50, 200))
                restaurant = str(rng.choice(_RESTAURANTS))
                template = str(rng.choice(_LIFESTYLE_TEMPLATES["fine_dining"]))
                raw_text = template.format(restaurant=restaurant, value=value, n=rng.integers(2, 6))
                source = str(rng.choice(["instagram_post", "public_notice"]))

            raw = {"signal_id": signal_id, "handle": handle, "type": sig_type,
                   "value_usd": value, "text": raw_text}
            records.append({
                "signal_id":            signal_id,
                "scraped_datetime":     _scraped_ts(day, rng),
                "handle":               handle,
                "signal_source":        source,
                "raw_text":             raw_text[:1000],
                "estimated_value_usd":  value,
                "raw_json":             json.dumps(raw),
            })

    df = pd.DataFrame(records)
    logger.info("Lifestyle: %d signals", len(df))
    return _write_csv(df, BRONZE_DIR / "raw_lifestyle_signals.csv", dry_run)


# ---------------------------------------------------------------------------
# Stream 4: Financial Stress Proxies
# ---------------------------------------------------------------------------

_FINANCIAL_TEMPLATES = {
    "civil_judgment": (
        "Civil judgment filed against {name}, Case #{case_num}, "
        "amount ${amount:,}, {county} Circuit Court, {state}"
    ),
    "lien": (
        "Tax lien notice: {name}, property at {address}, "
        "outstanding amount ${amount:,}, filed {state} revenue authority"
    ),
    "eviction_notice": (
        "Unlawful detainer action: {name} v. landlord, "
        "{county} General District Court, Case #{case_num}, rent owed ${amount:,}"
    ),
    "bankruptcy_filing": (
        "Bankruptcy petition: {name}, Chapter {chapter} filing, "
        "Case #{case_num}, {district} District, total debt est. ${amount:,}"
    ),
}

_COUNTIES = ["Montgomery County MD", "Fairfax County VA", "Arlington County VA",
             "Prince Georges County MD", "Alexandria City VA"]
_STATES   = ["Maryland", "Virginia", "DC"]


def generate_financial_stress(hris_df: pd.DataFrame, threat_ids: set[int], dry_run: bool) -> str:
    """Generate raw_financial_stress.csv."""
    rng = np.random.default_rng(RANDOM_SEED + 400)
    dates = _timeline_dates()

    records = []
    rec_seq = 1

    for i in range(EMPLOYEE_COUNT):
        emp_id = _employee_id(i)
        is_high_risk = i in threat_ids

        name_rows = hris_df[hris_df["employee_id"] == emp_id]["full_name"].values
        name_str = str(name_rows[0]) if len(name_rows) > 0 else fake.name()

        # Financial stress leads sentiment by 2-4 weeks (Days 15-35 for threat actors)
        for day_num, day in enumerate(dates):
            if is_high_risk and 15 <= day_num <= 35:
                stress_prob = 0.12  # elevated in lead window
            elif is_high_risk and day_num > 35:
                stress_prob = 0.05  # residual
            else:
                stress_prob = 0.01  # benign noise

            if rng.random() > stress_prob:
                continue

            record_id = f"FSR_{rec_seq:05d}"
            rec_seq += 1

            if is_high_risk and 15 <= day_num <= 35:
                rec_type = str(rng.choice(
                    ["civil_judgment", "lien", "eviction_notice", "bankruptcy_filing"],
                    p=[0.35, 0.30, 0.25, 0.10]
                ))
            else:
                rec_type = str(rng.choice(
                    ["civil_judgment", "lien", "eviction_notice", "bankruptcy_filing"],
                    p=[0.50, 0.30, 0.15, 0.05]
                ))

            county = str(rng.choice(_COUNTIES))
            state  = str(rng.choice(_STATES))
            case_num = f"{int(day.year)}-CV-{rng.integers(1000, 99999)}"
            chapter  = int(rng.choice([7, 13]))
            district = str(rng.choice(["Maryland", "Eastern Virginia", "DC"]))
            address  = f"{rng.integers(100, 9999)} {fake.street_name()}, {county}"

            amounts = {
                "civil_judgment":    int(rng.integers(3000,  25000)),
                "lien":              int(rng.integers(5000,  40000)),
                "eviction_notice":   int(rng.integers(1500,  8000)),
                "bankruptcy_filing": int(rng.integers(50000, 250000)),
            }
            amount = amounts[rec_type]

            template = _FINANCIAL_TEMPLATES[rec_type]
            raw_text = template.format(
                name=name_str, case_num=case_num, amount=amount,
                county=county, state=state, chapter=chapter,
                district=district, address=address,
            )

            src = str(rng.choice(["county_court_records", "state_filings",
                                   "public_notice", "bankruptcy_court"]))
            raw = {"record_id": record_id, "employee_id": emp_id,
                   "type": rec_type, "amount": amount, "text": raw_text}
            records.append({
                "record_id":        record_id,
                "scraped_datetime": _scraped_ts(day, rng),
                "employee_id":      emp_id,
                "source":           src,
                "raw_text":         raw_text[:1000],
                "raw_json":         json.dumps(raw),
            })

    df = pd.DataFrame(records)
    logger.info("Financial stress: %d records", len(df))
    return _write_csv(df, BRONZE_DIR / "raw_financial_stress.csv", dry_run)


# ---------------------------------------------------------------------------
# Stream 5: Dark Web Signals
# ---------------------------------------------------------------------------

_DARKWEB_TEMPLATES = {
    "credential_dump": (
        "Credential dump batch #{batch}: {credential} [verified active] "
        "— source: {site}"
    ),
    "data_paste": (
        "Pastebin entry #{batch}: internal data excerpt, possible exfil, "
        "matched identifier: {credential}"
    ),
    "pii_exposure": (
        "Data broker listing: {credential}, DOB, SSN partial, address — "
        "available on {site}"
    ),
    "forum_mention": (
        "Forum post on {site}: selling access, reference to {credential}, "
        "price quoted ${price}"
    ),
}

_DARK_SITES = ["BreachForums", "RaidForums", "HaveIBeenPwned feed",
               "Paste.ee", "Ghostbin", "0bin.net", "DeepPaste"]


def generate_darkweb(handles_df: pd.DataFrame, hris_df: pd.DataFrame,
                     threat_ids: set[int], dry_run: bool) -> str:
    """Generate raw_darkweb_signals.csv."""
    rng = np.random.default_rng(RANDOM_SEED + 500)
    dates = _timeline_dates()

    # Build email map from hris (simulate directory emails)
    emp_emails: dict[str, str] = {}
    if "full_name" in hris_df.columns:
        for _, row in hris_df.iterrows():
            name = str(row["full_name"]).lower().replace(" ", ".")
            emp_emails[str(row["employee_id"])] = f"{name}@company.com"

    handle_to_emp = handles_df.dropna(subset=["employee_id"]).set_index("social_handle")["employee_id"].to_dict()
    emp_handles: dict[str, str] = {}
    for _, row in handles_df.dropna(subset=["employee_id"]).iterrows():
        emp_handles[str(row["employee_id"])] = row["social_handle"]

    records = []
    det_seq = 1

    for i in range(EMPLOYEE_COUNT):
        emp_id = _employee_id(i)
        is_high_risk = i in threat_ids

        email  = emp_emails.get(emp_id, f"user{i+1}@company.com")
        handle = emp_handles.get(emp_id, f"user_{i+1:05d}")

        for day_num, day in enumerate(dates):
            # Dark web: random for benign (noise), correlated with data activity for threats
            # Threat correlation: Days 55-75 (per lead/lag spec)
            if is_high_risk and 55 <= day_num <= 75:
                detect_prob = 0.20
            elif is_high_risk:
                detect_prob = 0.04
            else:
                detect_prob = 0.02  # benign noise — random exposure

            if rng.random() > detect_prob:
                continue

            detection_id = f"DWS_{det_seq:05d}"
            det_seq += 1

            matched_on = str(rng.choice(["email", "social_handle"],
                                         p=[0.6, 0.4]))
            credential = email if matched_on == "email" else handle
            site = str(rng.choice(_DARK_SITES))
            batch = int(rng.integers(100, 9999))
            price = int(rng.integers(50, 5000))

            if is_high_risk and 55 <= day_num <= 75:
                sig_type = str(rng.choice(
                    ["credential_exposure", "pii_exposure", "data_paste", "forum_mention"],
                    p=[0.30, 0.25, 0.25, 0.20]
                ))
                severity = str(rng.choice(["medium", "high"], p=[0.4, 0.6]))
            else:
                sig_type = str(rng.choice(
                    ["credential_exposure", "pii_exposure", "data_paste", "forum_mention"],
                    p=[0.50, 0.20, 0.20, 0.10]
                ))
                severity = str(rng.choice(["low", "medium"], p=[0.7, 0.3]))

            # Map sig_type to template key
            template_key = {
                "credential_exposure": "credential_dump",
                "data_paste":          "data_paste",
                "pii_exposure":        "pii_exposure",
                "forum_mention":       "forum_mention",
            }[sig_type]

            raw_text = _DARKWEB_TEMPLATES[template_key].format(
                batch=batch, credential=credential,
                site=site, price=price,
            )

            src = str(rng.choice(["paste_site", "hacker_forum",
                                   "credential_dump", "data_broker"],
                                  p=[0.30, 0.25, 0.30, 0.15]))
            raw = {"detection_id": detection_id, "handle": handle,
                   "matched": matched_on, "type": sig_type,
                   "severity": severity, "text": raw_text}
            records.append({
                "detection_id":     detection_id,
                "scraped_datetime": _scraped_ts(day, rng),
                "handle":           credential,
                "signal_source":    src,
                "raw_text":         raw_text[:1000],
                "matched_on":       matched_on,
                "raw_json":         json.dumps(raw),
            })

    df = pd.DataFrame(records)
    logger.info("Dark web: %d detections", len(df))
    return _write_csv(df, BRONZE_DIR / "raw_darkweb_signals.csv", dry_run)


# ---------------------------------------------------------------------------
# Upload to MinIO
# ---------------------------------------------------------------------------

def _upload_osint_to_minio(paths: list[str], dry_run: bool) -> None:
    if dry_run:
        logger.info("[DRY-RUN] Would upload %d OSINT files to MinIO", len(paths))
        return
    try:
        import boto3
        from botocore.client import Config
        MINIO_ENDPOINT   = os.getenv("MINIO_ENDPOINT",   "")
        MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "")
        MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "")
        MINIO_BUCKET     = os.getenv("MINIO_BUCKET",     "sentinel-bronze")
        s3 = boto3.client(
            "s3",
            endpoint_url=MINIO_ENDPOINT,
            aws_access_key_id=MINIO_ACCESS_KEY,
            aws_secret_access_key=MINIO_SECRET_KEY,
            config=Config(signature_version="s3v4"),
        )
        for local_path in paths:
            fname = Path(local_path).name
            key   = f"{MINIO_OSINT_PREFIX}/{fname}"
            s3.upload_file(local_path, MINIO_BUCKET, key)
            logger.info("Uploaded %s -> s3://%s/%s", fname, MINIO_BUCKET, key)
    except Exception as exc:
        logger.error("MinIO upload failed: %s", exc)
        raise


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(dry_run: bool = False, env: str = "local", log_level: str = "INFO") -> dict:
    """
    Generate all 5 OSINT Bronze streams.
    Called by s1_generate_raw.run() or standalone.
    Returns standard stage result dict.
    """
    logging.getLogger().setLevel(log_level)
    _seed_all(RANDOM_SEED)
    t0 = time.perf_counter()

    logger.info("generate_osint_streams START | dry_run=%s env=%s seed=%d employees=%d days=%d",
                dry_run, env, RANDOM_SEED, EMPLOYEE_COUNT, TIMELINE_DAYS)

    threat_ids = _threat_actor_ids()
    logger.info("Threat actor cohort: %d employees identified (same seed as s1)", len(threat_ids))

    handles_df = _load_social_handles(dry_run)
    hris_df    = _load_hris(dry_run)

    artifacts: list[str] = []

    logger.info("Generating Stream 1: Twitter/X")
    artifacts.append(generate_twitter(handles_df, threat_ids, dry_run))

    logger.info("Generating Stream 2: Instagram/Location")
    artifacts.append(generate_instagram(handles_df, threat_ids, dry_run))

    logger.info("Generating Stream 3: Lifestyle Signals")
    artifacts.append(generate_lifestyle(handles_df, hris_df, threat_ids, dry_run))

    logger.info("Generating Stream 4: Financial Stress")
    artifacts.append(generate_financial_stress(hris_df, threat_ids, dry_run))

    logger.info("Generating Stream 5: Dark Web")
    artifacts.append(generate_darkweb(handles_df, hris_df, threat_ids, dry_run))

    _upload_osint_to_minio(artifacts, dry_run)

    duration = time.perf_counter() - t0
    rows_out  = sum(
        len(pd.read_csv(p)) for p in artifacts if not dry_run and Path(p).exists()
    )
    logger.info("generate_osint_streams DONE | files=%d rows_out=%d duration=%.2fs",
                len(artifacts), rows_out, duration)

    return {
        "status":           "success",
        "rows_in":          0,
        "rows_out":         rows_out,
        "duration_seconds": round(duration, 3),
        "artifacts":        artifacts,
    }


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="generate_osint_streams — OSINT Bronze data generation")
    p.add_argument("--dry-run",   action="store_true")
    p.add_argument("--env",       default="local", choices=["local", "dev", "prod"])
    p.add_argument("--log-level", default="INFO",  choices=["DEBUG", "INFO", "WARNING"])
    args = p.parse_args()
    result = run(dry_run=args.dry_run, env=args.env, log_level=args.log_level)
    sys.exit(0 if result["status"] == "success" else 1)
