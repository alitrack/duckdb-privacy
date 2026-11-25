//! fake — synthetic-data generator, 1:1 port of
//! `duckdb-luajit-libs/libs/fake/fake.lua` (958 lines, tested, 55 kinds).
//!
//! This is a *self-contained* port (no fake-rs dependency): duckdb-privacy is a
//! zero-dep native extension (quack-rs / libduckdb-sys / regex / aes only), so
//! the generator reuses the extension's own [`crate::rng::Rng`] (Park–Miller
//! LCG, bit-identical to the Lua `make_rng`). Consequence: the same `seed`
//! yields the same values here as in the original `luajit_s('fake', ...)`,
//! consistent with every other op in this extension.
//!
//! Ops (dispatched on the JSON `op` field, matching the Lua `run()`):
//!   kinds     → `{kinds:[...], count:N}`
//!   gen       → single value (bare string), `kind` (+ optional `:lo,hi` arg)
//!   template  → `{a.b}` placeholders + `#?` random hex, bare string
//!   rows      → JSON array of per-row JSON objects
//!   table     → bare `\n`-joined pipe rows (for the `fake` table function)
//!
//! Entity association (on by default): one "person" context is shared per row,
//! so name / email(local part = own name) / phone / city / state / zip / age /
//! date-of-birth all derive from the same entity (city→state/zip, age↔dob).
//! `spec.entity=false` disables it (independent per-column draws).
//!
//! Honest limit: word pools are built-in (~700 words: EN first/last 32 each, CN
//! surname 30 / given 30, cities 28, countries 32, industries 13, colors 15,
//! states 26, street suffixes 13). Distribution is uniform over the pool, not a
//! real population distribution. Default date window 2001-01-01..2020-12-31
//! (seed-stable; pass `date.iso:lo,hi` for a different window).

use crate::json::{self, Value};
use crate::rng::Rng;

// ── built-in word pools (ported verbatim from fake.lua) ──────────────────────

const FIRST_EN: &[&str] = &[
    "James", "Mary", "John", "Patricia", "Robert", "Jennifer", "Michael", "Linda", "David",
    "Elizabeth", "William", "Barbara", "Richard", "Susan", "Joseph", "Jessica", "Thomas",
    "Sarah", "Charles", "Karen", "Christopher", "Nancy", "Daniel", "Lisa", "Matthew", "Betty",
    "Anthony", "Sandra", "Mark", "Ashley", "Donald", "Emily", "Steven",
];
const LAST_EN: &[&str] = &[
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez",
    "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson", "Thomas", "Taylor",
    "Moore", "Jackson", "Martin", "Lee", "Perez", "Thompson", "White", "Harris", "Sanchez",
    "Clark", "Ramirez", "Lewis", "Robinson", "Walker", "Young",
];
const LAST_CN: &[&str] = &[
    "王", "李", "张", "刘", "陈", "杨", "赵", "黄", "周", "吴", "徐", "孙", "胡", "朱", "高",
    "林", "何", "郭", "马", "罗", "梁", "宋", "郑", "谢", "韩", "唐", "冯", "于", "董", "萧",
];
const GIVEN_CN_1: &[&str] = &[
    "伟", "芳", "娜", "敏", "静", "丽", "强", "磊", "军", "洋", "勇", "艳", "杰", "娟", "涛",
    "明", "超", "霞", "平", "刚", "斌", "鹏", "琳", "鑫", "宇", "浩", "博", "婷", "欣", "凯",
];
const GIVEN_CN_2: &[&str] = &[
    "秀英", "桂英", "建国", "建军", "志刚", "海燕", "淑珍", "淑兰", "玉兰", "玉梅", "丽华", "凤英",
    "美玲", "雪梅", "桂兰", "淑芬", "雅静", "雅芳", "志强", "国栋", "俊杰", "晓燕", "春梅",
    "秀梅", "玉华", "美华", "淑华", "凤仙", "桂香", "伟民",
];
const CITY_US: &[&str] = &[
    "New York", "Los Angeles", "Chicago", "Houston", "Phoenix", "Philadelphia", "San Antonio",
    "San Diego", "Dallas", "San Jose", "Austin", "Jacksonville", "Fort Worth", "Columbus",
    "Charlotte", "Indianapolis", "San Francisco", "Seattle", "Denver", "Boston", "Nashville",
    "Detroit", "Portland", "Las Vegas", "Memphis", "Louisville", "Baltimore", "Milwaukee",
];
const CITY_CN: &[&str] = &[
    "北京", "上海", "广州", "深圳", "杭州", "成都", "武汉", "西安", "南京", "重庆", "苏州", "天津",
    "长沙", "郑州", "东莞", "青岛", "沈阳", "宁波", "昆明", "合肥", "福州", "大连", "厦门", "无锡",
    "济南", "贵阳", "哈尔滨", "南宁",
];
const STATE_US: &[&str] = &[
    "Alabama", "Alaska", "Arizona", "Arkansas", "California", "Colorado", "Connecticut",
    "Delaware", "Florida", "Georgia", "Hawaii", "Idaho", "Illinois", "Indiana", "Iowa", "Kansas",
    "Kentucky", "Louisiana", "Maine", "Maryland", "Massachusetts", "Michigan", "Minnesota",
    "Mississippi", "Missouri", "Montana", "Nebraska", "Nevada", "New Hampshire", "New Jersey",
    "New Mexico", "New York",
];
const COUNTRY: &[&str] = &[
    "United States", "China", "Japan", "Germany", "United Kingdom", "France", "Canada",
    "Australia", "Brazil", "India", "Italy", "Spain", "Russia", "Mexico", "South Korea",
    "Netherlands", "Sweden", "Norway", "Denmark", "Switzerland", "Austria", "Belgium", "Finland",
    "Poland", "Ireland", "Portugal", "Greece", "Turkey", "Argentina", "Chile", "Colombia",
    "South Africa", "New Zealand",
];
const COUNTRY_ABBR: &[&str] = &[
    "US", "CN", "JP", "DE", "GB", "FR", "CA", "AU", "BR", "IN", "IT", "ES", "RU", "MX", "KR",
    "NL", "SE", "NO", "DK", "CH", "AT", "BE", "FI", "PL", "IE", "PT", "GR", "TR", "AR", "CL",
    "CO", "ZA", "NZ",
];
const STREET_NAME: &[&str] = &[
    "Main", "Oak", "Pine", "Maple", "Cedar", "Elm", "Washington", "Lake", "Hill", "Park",
    "Spring", "Sunset", "River", "Forest", "Meadow", "Highland",
];
const STREET_SUFFIX: &[&str] = &[
    "Street", "Avenue", "Boulevard", "Drive", "Lane", "Road", "Court", "Place", "Terrace",
    "Way", "Circle", "Path", "Crossing", "Parkway", "Trail", "Row",
];
const COMPANY_A: &[&str] = &[
    "Alpha", "Apex", "Blue", "Bright", "Cedar", "Delta", "Dynamo", "Everest", "Falcon", "Granite",
    "Harbor", "Iron", "Jade", "Keystone", "Lumen", "Maverick", "Nimbus", "Onyx", "Pacific",
    "Quantum", "Redwood", "Summit", "Titan", "Vertex",
];
const COMPANY_B: &[&str] = &[
    "Technologies", "Solutions", "Systems", "Dynamics", "Analytics", "Labs", "Group", "Partners",
    "Industries", "Networks", "Software", "Digital", "Media", "Logistics", "Robotics",
    "Security", "Energy", "Foods", "Airlines", "Insurance", "Capital", "Holdings", "Ventures",
    "Interactive",
];
const COMPANY_SUFFIX: &[&str] = &["Inc", "Corp", "LLC", "Ltd", "Co"];
const COLORS: &[&str] = &[
    "red", "orange", "yellow", "green", "blue", "purple", "pink", "brown", "black", "white",
    "gray", "silver", "gold", "teal", "maroon", "navy",
];
const WORDS: &[&str] = &[
    "data", "cloud", "network", "signal", "vector", "matrix", "orbit", "pulse", "spark",
    "ridge", "harbor", "summit", "meadow", "canyon", "glacier", "prairie", "willow", "cedar",
    "amber", "coral", "drift", "echo", "flux", "grove", "haven", "ionic", "jungle", "koala",
    "lagoon", "mist",
];
const JOBS: &[&str] = &[
    "Software Engineer", "Data Scientist", "Product Manager", "UX Designer", "DevOps Engineer",
    "Accountant", "Marketing Manager", "Sales Representative", "Teacher", "Nurse", "Lawyer",
    "Engineer", "Chef", "Writer", "Analyst", "Consultant", "Architect", "Photographer", "Driver",
    "Electrician",
];
const INDUSTRIES: &[&str] = &[
    "Technology", "Healthcare", "Finance", "Education", "Retail", "Manufacturing", "Energy",
    "Media", "Transportation", "Real Estate", "Consulting", "Hospitality", "Agriculture",
    "Construction", "Telecom",
];
const CAR_BRAND: &[&str] = &[
    "Toyota", "Honda", "Ford", "Tesla", "BMW", "Mercedes-Benz", "Audi", "Volkswagen", "Hyundai",
    "Kia", "Nissan", "Subaru", "Mazda", "Lexus",
];
const DOMAIN_TLD: &[&str] = &["com", "org", "net", "io", "co", "dev", "app", "tech", "ai", "xyz", "info", "me"];
const EMAIL_DOMAINS: &[&str] = &["example.com", "example.org", "example.net", "test.com", "mail.example.com"];
const PERSON_PREFIX: &[&str] = &["Mr.", "Mrs.", "Ms.", "Dr.", "Prof."];
const PERSON_SUFFIX: &[&str] = &["Jr.", "Sr.", "II", "III", "IV"];
const SENTENCE_CN_A: &[&str] = &[
    "今天的数据", "这个系统", "新的方案", "我们的产品", "这次调研", "数据库的性能", "接口的设计",
];
const SENTENCE_CN_B: &[&str] = &[
    "表现良好", "需要优化", "运行稳定", "提升明显", "有待改进", "符合预期", "超预期", "仍有瓶颈",
];

/// city → (state, zip-prefix) — the association layer (city decides state/zip).
fn city_info(city: &str) -> Option<(&'static str, &'static str)> {
    Some(match city {
        "New York" => ("New York", "10"),
        "Los Angeles" => ("California", "90"),
        "Chicago" => ("Illinois", "60"),
        "Houston" => ("Texas", "77"),
        "Phoenix" => ("Arizona", "85"),
        "Philadelphia" => ("Pennsylvania", "19"),
        "San Antonio" => ("Texas", "78"),
        "San Diego" => ("California", "92"),
        "Dallas" => ("Texas", "75"),
        "San Jose" => ("California", "95"),
        "Austin" => ("Texas", "78"),
        "Jacksonville" => ("Florida", "32"),
        "Fort Worth" => ("Texas", "76"),
        "Columbus" => ("Ohio", "43"),
        "Charlotte" => ("North Carolina", "28"),
        "Indianapolis" => ("Indiana", "46"),
        "San Francisco" => ("California", "94"),
        "Seattle" => ("Washington", "98"),
        "Denver" => ("Colorado", "80"),
        "Boston" => ("Massachusetts", "02"),
        "Nashville" => ("Tennessee", "37"),
        "Detroit" => ("Michigan", "48"),
        "Portland" => ("Oregon", "97"),
        "Las Vegas" => ("Nevada", "89"),
        "Memphis" => ("Tennessee", "38"),
        "Louisville" => ("Kentucky", "40"),
        "Baltimore" => ("Maryland", "21"),
        "Milwaukee" => ("Wisconsin", "53"),
        _ => return None,
    })
}

// ── RNG helpers (ported verbatim; same call order as the Lua) ───────────────

fn ri(rng: &mut Rng, lo: i64, hi: i64) -> i64 {
    let (lo, hi) = if hi < lo { (hi, lo) } else { (lo, hi) };
    lo + (rng.next_f64() * (hi - lo + 1) as f64).floor() as i64
}
fn pick(rng: &mut Rng, list: &'static [&'static str]) -> &'static str {
    let idx = ri(rng, 1, list.len() as i64) as usize - 1;
    list[idx]
}
fn rf(rng: &mut Rng, lo: f64, hi: f64, dp: u32) -> String {
    let (lo, hi) = if hi < lo { (hi, lo) } else { (lo, hi) };
    format!("{:.*}", dp as usize, lo + rng.next_f64() * (hi - lo))
}
fn shuffle(rng: &mut Rng, list: &'static [&'static str]) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = list.to_vec();
    for i in (1..out.len()).rev() {
        let j = ri(rng, 1, (i + 1) as i64) as usize - 1;
        out.swap(i, j);
    }
    out
}
fn gauss(rng: &mut Rng, mu: f64, sigma: f64) -> f64 {
    let u1 = rng.next_f64().max(1e-12);
    let u2 = rng.next_f64();
    mu + sigma * (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos()
}
fn lognormal(rng: &mut Rng, mu: f64, sigma: f64, dp: u32) -> String {
    format!("{:.*}", dp as usize, gauss(rng, mu, sigma).exp())
}

// ── date civil conversion (Howard Hinnant, ported) ──────────────────────────

const fn floor_div(a: i64, b: i64) -> i64 {
    let q = a / b;
    let r = a % b;
    if r != 0 && (a ^ b) < 0 { q - 1 } else { q }
}
const fn d2e(y: i64, m: i64, d: i64) -> i64 {
    let yy = y - (if m <= 2 { 1 } else { 0 });
    let era = floor_div(yy, 400);
    let yoe = yy - era * 400;
    let doy = floor_div(153 * (m + (if m > 2 { -3 } else { 9 })) + 2, 5) + d - 1;
    let doe = yoe * 365 + floor_div(yoe, 4) - floor_div(yoe, 100) + doy;
    era * 146097 + doe - 719468
}
fn e2d(z_in: i64) -> (i64, i64, i64) {
    let z = z_in + 719468;
    let era = floor_div(if z >= 0 { z } else { z - 146096 }, 146097);
    let doe = z - era * 146097;
    let yoe = floor_div(
        doe - floor_div(doe, 1460) + floor_div(doe, 36524) - floor_div(doe, 146096),
        365,
    );
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + floor_div(yoe, 4) - floor_div(yoe, 100));
    let mp = floor_div(5 * doy + 2, 153);
    let d = doy - floor_div(153 * mp + 2, 5) + 1;
    let m = mp + (if mp < 10 { 3 } else { -9 });
    (y + (if m <= 2 { 1 } else { 0 }), m, d)
}
const EPOCH_DEFAULT_LO: i64 = d2e(2001, 1, 1);
const EPOCH_DEFAULT_HI: i64 = d2e(2020, 12, 31);
fn fmt_date(z: i64) -> String {
    let (y, m, d) = e2d(z);
    format!("{:04}-{:02}-{:02}", y, m, d)
}
fn parse_date(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 10 || b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    let y: i64 = s[0..4].parse().ok()?;
    let m: i64 = s[5..7].parse().ok()?;
    let d: i64 = s[8..10].parse().ok()?;
    Some(d2e(y, m, d))
}
fn rand_epoch_day(rng: &mut Rng, lo_s: &str, hi_s: &str) -> i64 {
    let mut lo = EPOCH_DEFAULT_LO;
    let mut hi = EPOCH_DEFAULT_HI;
    if !lo_s.is_empty() {
        if let Some(z) = parse_date(lo_s) {
            lo = z;
        }
    }
    if !hi_s.is_empty() {
        if let Some(z) = parse_date(hi_s) {
            hi = z;
        }
    }
    ri(rng, lo, hi)
}
fn fmt_hm(rng: &mut Rng) -> String {
    format!("{:02}:{:02}", ri(rng, 0, 23), ri(rng, 0, 59))
}
fn fmt_hms(rng: &mut Rng) -> String {
    format!("{:02}:{:02}:{:02}", ri(rng, 0, 23), ri(rng, 0, 59), ri(rng, 0, 59))
}

// ── per-row entity context (association layer; ported verbatim) ─────────────

#[derive(Default)]
struct PersonCtx {
    first: Option<String>,
    last: Option<String>,
    first_cn: Option<String>,
    gender: Option<String>,
    email: Option<String>,
    phone: Option<String>,
    city: Option<String>,
    state: Option<String>,
    zip: Option<String>,
    birth_year: Option<i64>,
}

fn cn_given(rng: &mut Rng) -> &'static str {
    if rng.next_f64() < 0.55 {
        pick(rng, GIVEN_CN_2)
    } else {
        pick(rng, GIVEN_CN_1)
    }
}
impl PersonCtx {
    fn first(&mut self, rng: &mut Rng) -> &str {
        if self.first.is_none() {
            self.first = Some(pick(rng, FIRST_EN).to_string());
        }
        self.first.as_ref().unwrap()
    }
    fn last(&mut self, rng: &mut Rng) -> &str {
        if self.last.is_none() {
            self.last = Some(pick(rng, LAST_EN).to_string());
        }
        self.last.as_ref().unwrap()
    }
    fn full(&mut self, rng: &mut Rng) -> String {
        let f = self.first(rng).to_string();
        let l = self.last(rng).to_string();
        format!("{} {}", f, l)
    }
    fn first_cn(&mut self, rng: &mut Rng) -> &str {
        if self.first_cn.is_none() {
            self.first_cn = Some(format!("{}{}", pick(rng, LAST_CN), cn_given(rng)));
        }
        self.first_cn.as_ref().unwrap()
    }
    fn gender(&mut self, rng: &mut Rng) -> &str {
        if self.gender.is_none() {
            self.gender = Some(if rng.next_f64() < 0.5 { "male" } else { "female" }.to_string());
        }
        self.gender.as_ref().unwrap()
    }
    fn email(&mut self, rng: &mut Rng) -> &str {
        if self.email.is_none() {
            let fn_ = self.first(rng).to_lowercase();
            let ln = self.last(rng).to_lowercase();
            let r = rng.next_f64();
            let local = if r < 0.34 {
                format!("{fn_}.{ln}")
            } else if r < 0.67 {
                format!("{fn_}{}", ri(rng, 1, 99))
            } else {
                format!("{fn_}.{ln}{}", ri(rng, 1, 999))
            };
            self.email = Some(format!("{local}@{}", pick(rng, EMAIL_DOMAINS)));
        }
        self.email.as_ref().unwrap()
    }
    fn phone(&mut self, rng: &mut Rng) -> &str {
        if self.phone.is_none() {
            self.phone = Some(format!(
                "({:03}) {:03}-{:04}",
                ri(rng, 200, 989),
                ri(rng, 200, 989),
                ri(rng, 0, 9999)
            ));
        }
        self.phone.as_ref().unwrap()
    }
    fn city(&mut self, rng: &mut Rng) -> &str {
        if self.city.is_none() {
            self.city = Some(pick(rng, CITY_US).to_string());
        }
        self.city.as_ref().unwrap()
    }
    fn state(&mut self, rng: &mut Rng) -> &str {
        if self.state.is_none() {
            let c = self.city(rng);
            self.state = Some(
                city_info(c)
                    .map(|(st, _)| st.to_string())
                    .unwrap_or_else(|| pick(rng, STATE_US).to_string()),
            );
        }
        self.state.as_ref().unwrap()
    }
    fn zip(&mut self, rng: &mut Rng) -> &str {
        if self.zip.is_none() {
            let c = self.city(rng);
            self.zip = Some(match city_info(c) {
                Some((_, prefix)) => format!("{prefix}{:03}", ri(rng, 0, 999)),
                None => format!("{:05}", ri(rng, 10000, 99999)),
            });
        }
        self.zip.as_ref().unwrap()
    }
    fn birth_year(&mut self, rng: &mut Rng) -> i64 {
        if self.birth_year.is_none() {
            self.birth_year = Some(ri(rng, 1961, 2008));
        }
        self.birth_year.unwrap()
    }
}

// ── JSON string escaping (for json row output; ported from jsesc) ───────────

fn jsesc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

// ── column-name → kind inference (ported; exact map then fuzzy rules) ───────

fn exact_kind(low: &str) -> Option<&'static str> {
    Some(match low {
        "id" => "uuid",
        "name" | "full_name" => "person.full",
        "full_name_cn" => "person.full_cn",
        "first_name" => "person.first",
        "last_name" => "person.last",
        "name_cn" => "person.first_cn",
        "user_name" | "username" => "person.username",
        "gender" => "person.gender",
        "email" | "email_address" => "contact.email",
        "phone" | "phone_number" | "mobile" => "contact.phone",
        "tel" => "contact.phone_unformatted",
        "company" | "company_name" | "employer" => "company.name",
        "job" | "job_title" | "title" => "company.job_title",
        "industry" => "company.industry",
        "street" => "address.street",
        "address" | "addr" | "full_address" => "address.full",
        "city" => "address.city_us",
        "city_cn" | "province" => "address.city_cn",
        "state" | "region" => "address.state",
        "country" => "address.country",
        "zip" | "zip_code" | "postal" | "postal_code" => "address.zip",
        "lat" | "latitude" => "address.lat",
        "lon" | "lng" | "longitude" => "address.lon",
        "street_number" => "address.street_number",
        "domain" => "internet.domain",
        "website" | "url" | "web_site" => "internet.url",
        "ip" | "ip_address" => "internet.ip",
        "amount" | "price" | "salary" | "revenue" | "cost" | "fee" | "total" => "finance.amount",
        "card" | "card_number" | "credit_card" => "card.number",
        "cvv" => "card.cvv",
        "car" | "car_brand" => "car.brand",
        "color" => "color.name",
        "hex_color" | "color_hex" => "color.hex",
        "word" => "text.word",
        "words" => "text.words",
        "sentence" | "text" | "paragraph" | "note" | "comment" | "description" | "bio" => {
            "text.sentence"
        }
        "sentence_cn" => "text.sentence_cn",
        "slug" => "text.slug",
        "date" => "date.iso",
        "created_at" | "updated_at" | "created" | "updated" => "date.datetime",
        "birth_date" | "birthday" | "dob" => "person.dob",
        "age" => "person.age",
        "date_cn" => "time.date_cn",
        "time" => "time.hm",
        "uuid" => "uuid",
        _ => return None,
    })
}
fn guess_kind(colname: &str) -> &'static str {
    let low: String = {
        let mut s = colname.trim().to_lowercase();
        s = s.replace(' ', "_");
        while s.starts_with('_') {
            s.remove(0);
        }
        while s.ends_with('_') {
            s.pop();
        }
        s
    };
    if low.is_empty() {
        return "text.word";
    }
    if let Some(k) = exact_kind(&low) {
        return k;
    }
    // fuzzy rules, in priority order (substring match; "_at$" = ends with "_at")
    let rules: &[(&str, &str)] = &[
        ("_at", "date.datetime"),
        ("email", "contact.email"),
        ("phone", "contact.phone"),
        ("name", "person.full"),
        ("user", "person.username"),
        ("lat", "address.lat"),
        ("lon", "address.lon"),
        ("zip", "address.zip"),
        ("city", "address.city_us"),
        ("country", "address.country"),
        ("street", "address.street"),
        ("address", "address.full"),
        ("company", "company.name"),
        ("job", "company.job_title"),
        ("domain", "internet.domain"),
        ("url", "internet.url"),
        ("ip", "internet.ip"),
        ("amount", "finance.amount"),
        ("price", "finance.amount"),
        ("card", "card.number"),
        ("car", "car.brand"),
        ("color", "color.name"),
        ("bool", "bool.b"),
        ("date", "date.iso"),
        ("uuid", "uuid"),
        ("word", "text.word"),
        ("text", "text.sentence"),
    ];
    for (pat, kind) in rules {
        if low.contains(pat) || (pat.starts_with('_') && low.ends_with(&pat[1..])) {
            return kind;
        }
    }
    "text.word"
}

// ── single-kind generator (ported verbatim; ctx = per-row entity) ───────────

fn gen_kind(rng: &mut Rng, ctx: Option<&mut PersonCtx>, kind_str: &str) -> Result<String, String> {
    let (name, a1) = match kind_str.split_once(':') {
        Some((n, a)) => (n, Some(a)),
        None => (kind_str, None),
    };
    match name {
        "person.first" => Ok(match ctx {
            Some(c) => c.first(rng).to_string(),
            None => pick(rng, FIRST_EN).to_string(),
        }),
        "person.last" => Ok(match ctx {
            Some(c) => c.last(rng).to_string(),
            None => pick(rng, LAST_EN).to_string(),
        }),
        "person.full" => Ok(match ctx {
            Some(c) => c.full(rng),
            None => format!("{} {}", pick(rng, FIRST_EN), pick(rng, LAST_EN)),
        }),
        "person.first_cn" | "person.full_cn" => Ok(match ctx {
            Some(c) => c.first_cn(rng).to_string(),
            None => format!("{}{}", pick(rng, LAST_CN), cn_given(rng)),
        }),
        "person.gender" => Ok(match ctx {
            Some(c) => c.gender(rng).to_string(),
            None => if rng.next_f64() < 0.5 { "male" } else { "female" }.to_string(),
        }),
        "person.username" => {
            let fn_ = pick(rng, FIRST_EN).to_lowercase();
            let ln = pick(rng, LAST_EN).to_lowercase();
            let r = rng.next_f64();
            let sep = if r < 0.4 { "_" } else if r < 0.7 { "." } else { "" };
            let mut s = format!("{fn_}{sep}{ln}");
            if rng.next_f64() < 0.4 {
                s.push_str(&ri(rng, 1, 99).to_string());
            }
            Ok(s)
        }
        "person.prefix" => Ok(pick(rng, PERSON_PREFIX).to_string()),
        "person.suffix" => Ok(pick(rng, PERSON_SUFFIX).to_string()),
        "contact.email" => Ok(match ctx {
            Some(c) => c.email(rng).to_string(),
            None => {
                let fn_ = pick(rng, FIRST_EN).to_lowercase();
                let ln = pick(rng, LAST_EN).to_lowercase();
                let r = rng.next_f64();
                let local = if r < 0.34 {
                    format!("{fn_}.{ln}")
                } else if r < 0.67 {
                    format!("{fn_}{}", ri(rng, 1, 99))
                } else {
                    format!("{fn_}.{ln}{}", ri(rng, 1, 999))
                };
                format!("{local}@{}", pick(rng, EMAIL_DOMAINS))
            }
        }),
        "contact.phone" => Ok(match ctx {
            Some(c) => c.phone(rng).to_string(),
            None => format!(
                "({:03}) {:03}-{:04}",
                ri(rng, 200, 989),
                ri(rng, 200, 989),
                ri(rng, 0, 9999)
            ),
        }),
        "contact.phone_unformatted" => Ok(format!(
            "{:03}{:03}{:04}",
            ri(rng, 200, 989),
            ri(rng, 200, 989),
            ri(rng, 0, 9999)
        )),
        "company.name" => {
            let mut s = format!("{} {}", pick(rng, COMPANY_A), pick(rng, COMPANY_B));
            if rng.next_f64() < 0.5 {
                s.push(' ');
                s.push_str(pick(rng, COMPANY_SUFFIX));
            }
            Ok(s)
        }
        "company.job_title" => Ok(pick(rng, JOBS).to_string()),
        "company.industry" => Ok(pick(rng, INDUSTRIES).to_string()),
        "car.brand" => Ok(pick(rng, CAR_BRAND).to_string()),
        "address.street" => Ok(format!(
            "{} {} {}",
            ri(rng, 1, 9999),
            pick(rng, STREET_NAME),
            pick(rng, STREET_SUFFIX)
        )),
        "address.street_number" => Ok(ri(rng, 1, 9999).to_string()),
        "address.city_us" => Ok(match ctx {
            Some(c) => c.city(rng).to_string(),
            None => pick(rng, CITY_US).to_string(),
        }),
        "address.city_cn" => Ok(pick(rng, CITY_CN).to_string()),
        "address.state" => Ok(match ctx {
            Some(c) => c.state(rng).to_string(),
            None => pick(rng, STATE_US).to_string(),
        }),
        "address.country" => Ok(COUNTRY[ri(rng, 1, COUNTRY.len() as i64) as usize - 1].to_string()),
        "address.country_abbr" => Ok(
            COUNTRY_ABBR[ri(rng, 1, COUNTRY_ABBR.len() as i64) as usize - 1].to_string(),
        ),
        "address.zip" => Ok(match ctx {
            Some(c) => c.zip(rng).to_string(),
            None => format!("{:05}", ri(rng, 10000, 99999)),
        }),
        "address.lat" => Ok(rf(rng, -90.0, 90.0, 6)),
        "address.lon" => Ok(rf(rng, -180.0, 180.0, 6)),
        "address.full" => {
            let out = if let Some(c) = ctx {
                let num = ri(rng, 1, 9999);
                let sn = pick(rng, STREET_NAME).to_string();
                let ss = pick(rng, STREET_SUFFIX).to_string();
                let city = c.city(rng).to_string();
                let state = c.state(rng).to_string();
                let zip = c.zip(rng).to_string();
                format!("{} {} {}, {}, {} {}", num, sn, ss, city, state, zip)
            } else {
                let num = ri(rng, 1, 9999);
                let sn = pick(rng, STREET_NAME).to_string();
                let ss = pick(rng, STREET_SUFFIX).to_string();
                let city = pick(rng, CITY_US).to_string();
                let state = pick(rng, STATE_US).to_string();
                let zip = ri(rng, 10000, 99999);
                format!("{} {} {}, {}, {} {}", num, sn, ss, city, state, zip)
            };
            Ok(out)
        },
        "number.int" | "int" => {
            let a1 = a1.unwrap_or("");
            if a1.is_empty() {
                return Ok(ri(rng, 0, 9999).to_string());
            }
            let parts: Vec<&str> = a1.split(',').collect();
            if parts.len() != 2 {
                return Err(format!("number.int:lo,hi parse failed: {a1}"));
            }
            let lo: i64 = parts[0].parse().map_err(|_| a1.to_string())?;
            let hi: i64 = parts[1].parse().map_err(|_| a1.to_string())?;
            Ok(ri(rng, lo, hi).to_string())
        }
        "number.float" => Ok(rf(rng, 0.0, 1.0, 7)),
        "number.hex" => Ok(format!("{:08x}", ri(rng, 0, 0xFFFF_FFFF))),
        "number.float_range" => {
            let a1 = a1.unwrap_or("");
            if a1.is_empty() {
                return Err("number.float_range:lo,hi required".into());
            }
            let parts: Vec<&str> = a1.split(',').collect();
            if parts.len() < 2 {
                return Err(format!("number.float_range:lo,hi[,dp] parse failed: {a1}"));
            }
            let lo: f64 = parts[0].parse().map_err(|_| a1.to_string())?;
            let hi: f64 = parts[1].parse().map_err(|_| a1.to_string())?;
            let dp = parts.get(2).and_then(|d| d.parse().ok()).unwrap_or(3);
            Ok(rf(rng, lo, hi, dp as u32))
        }
        "bool.b" => Ok(if rng.next_f64() < 0.5 { "true" } else { "false" }.to_string()),
        "text.word" => Ok(WORDS[ri(rng, 1, WORDS.len() as i64) as usize - 1].to_lowercase()),
        "text.words" => {
            let n = ri(rng, 2, 5) as usize;
            Ok(shuffle(rng, WORDS)
                .into_iter()
                .take(n)
                .map(|w| w.to_lowercase())
                .collect::<Vec<_>>()
                .join(" "))
        }
        "text.sentence" => {
            let n = ri(rng, 3, 8) as usize;
            let w = shuffle(rng, WORDS)
                .into_iter()
                .take(n)
                .map(|x| x.to_lowercase())
                .collect::<Vec<_>>()
                .join(" ");
            Ok(format!("{w}."))
        }
        "text.sentence_cn" => {
            let s = pick(rng, SENTENCE_CN_A);
            let v = pick(rng, SENTENCE_CN_B);
            Ok(format!("{s}{v}。"))
        }
        "text.slug" => {
            let n = ri(rng, 2, 3) as usize;
            Ok(shuffle(rng, WORDS)
                .into_iter()
                .take(n)
                .map(|w| w.to_lowercase())
                .collect::<Vec<_>>()
                .join("-"))
        }
        "color.name" => Ok(pick(rng, COLORS).to_string()),
        "color.hex" => Ok(format!(
            "#{:02x}{:02x}{:02x}",
            ri(rng, 0, 255),
            ri(rng, 0, 255),
            ri(rng, 0, 255)
        )),
        "uuid" | "uuid_v4" => {
            let mut b: Vec<u8> = Vec::with_capacity(16);
            for i in 0..16 {
                let mut x = ri(rng, 0, 255) as u8;
                if i == 6 {
                    x = (x & 0x0F) | 0x40; // version 4
                }
                if i == 8 {
                    x = (x & 0x3F) | 0x80; // variant 10xx
                }
                b.push(x);
            }
            let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
            Ok(format!(
                "{}-{}-{}-{}-{}",
                &hex[0..8],
                &hex[8..12],
                &hex[12..16],
                &hex[16..20],
                &hex[20..32]
            ))
        }
        "internet.domain" => Ok(format!(
            "{}{}.{}",
            pick(rng, WORDS),
            ri(rng, 1, 999),
            pick(rng, DOMAIN_TLD)
        )),
        "internet.url" => Ok(format!(
            "https://www.{}{}.{}",
            pick(rng, WORDS),
            ri(rng, 1, 999),
            pick(rng, DOMAIN_TLD)
        )),
        "internet.ip" => Ok(format!(
            "{}.{}.{}.{}",
            ri(rng, 1, 254),
            ri(rng, 0, 255),
            ri(rng, 0, 255),
            ri(rng, 1, 254)
        )),
        "finance.amount" => Ok(lognormal(rng, 3.55, 1.6, 2)),
        "finance.salary" => Ok(lognormal(rng, 10.9, 0.55, 0)),
        "card.number" => {
            let mut s = String::new();
            for i in 0..4 {
                if i > 0 {
                    s.push(' ');
                }
                s.push_str(&format!("{:04}", ri(rng, 0, 9999)));
            }
            Ok(s)
        }
        "card.cvv" => Ok(format!("{:03}", ri(rng, 0, 999))),
        "date.iso" => {
            let (lo_s, hi_s) = a1
                .map(|a| {
                    let mut it = a.splitn(2, ',');
                    (
                        it.next().unwrap_or("").to_string(),
                        it.next().unwrap_or("").to_string(),
                    )
                })
                .unwrap_or_default();
            Ok(fmt_date(rand_epoch_day(rng, &lo_s, &hi_s)))
        }
        "date.datetime" => {
            let (lo_s, hi_s) = a1
                .map(|a| {
                    let mut it = a.splitn(2, ',');
                    (
                        it.next().unwrap_or("").to_string(),
                        it.next().unwrap_or("").to_string(),
                    )
                })
                .unwrap_or_default();
            Ok(format!("{} {}", fmt_date(rand_epoch_day(rng, &lo_s, &hi_s)), fmt_hms(rng)))
        }
        "date.day" => Ok(ri(rng, 1, 31).to_string()),
        "time.hm" => Ok(fmt_hm(rng)),
        "time.date_cn" => {
            let (lo_s, hi_s) = a1
                .map(|a| {
                    let mut it = a.splitn(2, ',');
                    (
                        it.next().unwrap_or("").to_string(),
                        it.next().unwrap_or("").to_string(),
                    )
                })
                .unwrap_or_default();
            let (y, m, d) = e2d(rand_epoch_day(rng, &lo_s, &hi_s));
            Ok(format!("{y}年{m}月{d}日"))
        }
        "person.age" => Ok(match ctx {
            Some(c) => (2026 - c.birth_year(rng)).to_string(),
            None => ri(rng, 18, 65).to_string(),
        }),
        "person.dob" => {
            let by = match ctx {
                Some(c) => c.birth_year(rng),
                None => ri(rng, 1961, 2008),
            };
            Ok(fmt_date(d2e(by, ri(rng, 1, 12), ri(rng, 1, 28))))
        }
        _ => Err(format!("unknown kind: {name}")),
    }
}

// ── template expansion: {a.b} placeholders + #? random hex ──────────────────

fn expand_template(rng: &mut Rng, template: &str) -> String {
    // {a.b} placeholders
    let mut out = String::new();
    let mut i = 0;
    let bytes = template.as_bytes();
    while i < bytes.len() {
        if bytes[i] == b'{' {
            if let Some(end) = template[i..].find('}') {
                let key = &template[i + 1..i + end];
                if !key.is_empty()
                    && key
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
                {
                    match gen_kind(rng, None, key) {
                        Ok(v) => out.push_str(&v),
                        Err(_) => out.push_str(&format!("{{{key}}}")),
                    }
                    i += end + 1;
                    continue;
                }
            }
            out.push('{');
            i += 1;
            continue;
        }
        // #? → random hex nibble
        if bytes[i] == b'#' && i + 1 < bytes.len() && bytes[i + 1] == b'?' {
            out.push_str(&format!("{:x}", ri(rng, 0, 15)));
            i += 2;
            continue;
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

// ── row-level generation (op=rows / op=table / table function) ──────────────

fn build_rows_inner(spec: &Value, outer_seed: Option<f64>) -> Result<Vec<String>, String> {
    let spec = match spec {
        Value::Obj(_) => spec,
        _ => return Err("spec must be a table (JSON string or struct)".into()),
    };
    let cols = match spec.get("cols") {
        Some(c) if c.is_obj() => c,
        _ => return Err("spec.cols required: {col: 'kind', ...}".into()),
    };
    // collect column names (stable: sorted), preserve value order via the obj
    let mut names: Vec<String> = match cols {
        Value::Obj(p) => p.iter().map(|(k, _)| k.clone()).collect(),
        _ => return Err("spec.cols must be an object".into()),
    };
    if names.is_empty() {
        return Err("spec.cols required: {col: 'kind', ...}".to_string());
    }
    names.sort();

    let n = spec
        .get("rows")
        .and_then(|v| match v {
            Value::Num(x) => Some(*x as i64),
            _ => None,
        })
        .unwrap_or(10);
    if n < 1 || n > 100_000 {
        return Err("spec.rows must be an integer in [1, 100000]".into());
    }
    let fmt_json = spec.get_s("format") == Some("json");
    let entity = spec.get("entity").map(|e| e != &Value::Bool(false)).unwrap_or(true);

    let seed = spec
        .get_f("seed")
        .or(outer_seed)
        .unwrap_or(0.0) as i64;
    let mut rng = Rng::new(seed);

    // pre-resolve each column's effective kind (explicit wins; empty/=colname → infer)
    let kind_of: Vec<(String, String)> = names
        .iter()
        .map(|k| {
            let s = cols.get(k).map(json::to_str_lossy).unwrap_or_default();
            let kind = if s.is_empty() || s.eq_ignore_ascii_case(k) {
                guess_kind(k).to_string()
            } else {
                s
            };
            (k.clone(), kind)
        })
        .collect();

    let mut rows = Vec::with_capacity(n as usize);
    for _ in 0..n {
        let mut ctx = if entity { Some(PersonCtx::default()) } else { None };
        let mut cells: Vec<(String, String)> = Vec::new();
        for (k, kind) in &kind_of {
            match gen_kind(&mut rng, ctx.as_mut(), kind) {
                Ok(v) => cells.push((k.clone(), v)),
                Err(e) => return Err(e),
            }
        }
        if fmt_json {
            let parts: Vec<String> = cells
                .iter()
                .map(|(k, v)| format!("\"{}\":\"{}\"", jsesc(k), jsesc(v)))
                .collect();
            rows.push(format!("{{{}}}", parts.join(",")));
        } else {
            let parts: Vec<String> = cells
                .iter()
                .map(|(_, v)| {
                    v.replace('\\', "\u{0007}")
                        .replace('|', "\u{0007}p")
                        .replace('\n', "\u{0007}n")
                        .replace('\r', "\u{0007}r")
                })
                .collect();
            rows.push(parts.join("|"));
        }
    }
    Ok(rows)
}

// ── the dispatcher (matches privacy's fn(v) -> String contract) ─────────────

fn err_obj(msg: &str) -> String {
    json::encode(&Value::Obj(vec![
        ("status".into(), Value::Str("Error".into())),
        ("message".into(), Value::Str(msg.to_string())),
    ]))
}

/// Build N row-strings from a spec (JSON string or parsed Value).
/// Used by the `fake` table function and by `op=rows`.
pub fn build_rows(spec: &Value) -> Result<Vec<String>, String> {
    let spec = match spec {
        Value::Str(s) => match crate::json::decode(s) {
            Ok(v) => v,
            Err(_) => return Err("spec must be valid JSON".into()),
        },
        other => other.clone(),
    };
    build_rows_inner(&spec, None)
}

/// `privacy('{op:"fake", ...}')` → output byte-compatible with the Lua `run()`.
pub fn fake(v: &Value) -> String {
    if !v.is_obj() {
        return String::new();
    }
    // "fake" is the module-level op (outer dispatch); filter it so the
    // default sub-op is "gen".  Rows/template/kinds arrive as their own op.
    let op = v
        .get("op")
        .map(json::to_str_lossy)
        .filter(|s| !s.is_empty() && *s != "fake")
        .unwrap_or_else(|| "gen".into());
    let seed = v.get_f("seed");

    match op.as_str() {
        "kinds" => {
            let kinds = all_kinds();
            let count = kinds.len() as i64;
            json::encode(&Value::Obj(vec![
                ("kinds".into(), Value::Arr(kinds.iter().map(|k| Value::Str(k.to_string())).collect())),
                ("count".into(), Value::Num(count as f64)),
            ]))
        }
        "gen" => {
            let kind = v.get_s("kind");
            let kind = match kind {
                Some(k) => k,
                None => return err_obj("missing kind"),
            };
            let mut rng = Rng::new(seed.unwrap_or(0.0) as i64);
            match gen_kind(&mut rng, None, kind) {
                Ok(s) => s,
                Err(e) => err_obj(&e),
            }
        }
        "template" => {
            let t = v.get_s("template");
            let t = match t {
                Some(t) => t,
                None => return err_obj("missing template"),
            };
            let mut rng = Rng::new(seed.unwrap_or(0.0) as i64);
            expand_template(&mut rng, t)
        }
        "rows" | "table" => {
            // spec: nested v.spec or the top-level v itself (convenience)
            let spec: &Value = match v.get("spec") {
                Some(s) => s,
                None => v, // use top-level object as the spec
            };
            if !spec.is_obj() {
                return err_obj("spec must be a table or JSON string");
            }
            match build_rows_inner(spec, seed) {
                Ok(rows) => {
                    if op == "table" {
                        rows.join("\n")
                    } else {
                        json::encode(&Value::Arr(rows.into_iter().map(Value::Str).collect()))
                    }
                }
                Err(e) => err_obj(&e),
            }
        }
        _ => err_obj(&format!("unknown op: {op}")),
    }
}

/// The 55 registered kind names (for op=kinds), in registration order.
fn all_kinds() -> Vec<&'static str> {
    vec![
        "person.first", "person.last", "person.full", "person.first_cn", "person.gender",
        "contact.email", "contact.phone", "company.name", "address.street", "address.city_us",
        "address.city_cn", "address.state", "address.country", "address.country_abbr",
        "number.int", "int", "number.float", "number.hex", "bool.b", "text.word", "text.words",
        "text.sentence", "text.slug", "color.name", "color.hex", "uuid", "uuid_v4",
        "person.username", "person.prefix", "person.suffix", "contact.phone_unformatted",
        "address.street_number", "address.zip", "address.lat", "address.lon", "address.full",
        "internet.domain", "internet.url", "internet.ip", "finance.amount", "finance.salary",
        "card.number", "card.cvv", "company.job_title", "company.industry", "car.brand",
        "text.sentence_cn", "number.float_range", "date.iso", "date.datetime", "date.day",
        "time.hm", "time.date_cn", "person.age", "person.dob",
    ]
}

// ── tests (parity anchors for the port) ─────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn g(kind: &str) -> String {
        let v = json::obj(vec![
            ("op", Value::Str("gen".into())),
            ("kind", Value::Str(kind.to_string())),
            ("seed", Value::Num(42.0)),
        ]);
        fake(&v)
    }

    #[test]
    fn gen_bare_value() {
        let s = g("person.last");
        assert!(LAST_EN.contains(&s.as_str()), "got {s}");
        let i = g("int:18,65");
        let n: i64 = i.parse().unwrap();
        assert!((18..=65).contains(&n), "got {i}");
    }
    #[test]
    fn seed_reproducible() {
        assert_eq!(g("person.full"), g("person.full"));
        assert_eq!(g("contact.email"), g("contact.email"));
    }
    #[test]
    fn template_expands() {
        let v = json::obj(vec![
            ("op", Value::Str("template".into())),
            ("template", Value::Str("{person.full} <{contact.email}> #?".into())),
            ("seed", Value::Num(7.0)),
        ]);
        let s = fake(&v);
        assert!(!s.contains('{') && !s.contains("}"), "unexpanded: {s}");
        assert!(s.contains('@'));
    }
    #[test]
    fn rows_entity_associated() {
        // same seed, age & dob from the same entity → consistent
        let v = json::obj(vec![
            ("op", Value::Str("rows".into())),
            ("seed", Value::Num(3.0)),
            (
                "spec",
                Value::Obj(vec![
                    (
                        "cols".into(),
                        Value::Obj(vec![
                            ("age".into(), Value::Str("person.age".into())),
                            ("dob".into(), Value::Str("person.dob".into())),
                        ]),
                    ),
                    ("rows".into(), Value::Num(5.0)),
                ]),
            ),
        ]);
        let s = fake(&v);
        assert!(s.starts_with('['), "expected JSON array: {s}");
    }
    #[test]
    fn unknown_kind_errors() {
        let v = json::obj(vec![
            ("op", Value::Str("gen".into())),
            ("kind", Value::Str("nope".into())),
        ]);
        let s = fake(&v);
        assert!(s.contains("\"Error\""), "got {s}");
    }
    #[test]
    fn luhn_and_id_style() {
        assert_eq!(g("card.cvv").len(), 3);
        assert_eq!(g("uuid").len(), 36);
        assert!(g("color.hex").starts_with('#'));
    }
}
