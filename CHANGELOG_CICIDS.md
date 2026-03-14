# CHANGELOG - CIC-IDS Integration

## [2026-03-14] - CIC-IDS 2017 Dataset Integration

### Added
- **`dashboard/cicids_loader.py`**: New module for loading and preprocessing CIC-IDS 2017 datasets
  - Robust CSV encoding detection (utf-8, latin-1, cp1252)
  - Synthetic timestamp generation (24-hour spread with attack clustering)
  - Synthetic IP address mapping (attacker vs normal ranges)
  - Column mapping from CIC-IDS format to dashboard schema
  - Confidence score calculation from flow features
  - Attack type classification and severity mapping
  - Threat-level assignment (ALERT/WATCH based on confidence)

### Changed
- **`dashboard/dashboard_app.py`**:
  - Updated `load_data()` with priority loading:
    1. CIC-IDS dataset (primary)
    2. AlertAgent logs (fallback)
    3. Demo data (last resort)
  - Added `CICIDS_PATH` constant for dataset location
  - Improved timezone handling (consistent tz-naive UTC)
  - Added debug comments for troubleshooting (commented out by default)

### Fixed
- **Encoding issues**: Multi-encoding fallback prevents UnicodeDecodeError
- **Timezone comparison errors**: All timestamps normalized to tz-naive UTC
- **Empty dashboard**: Now loads 158,930 real threat records from CIC-IDS

### Technical Details

#### Encoding Handling
```python
for enc in ("utf-8", "latin-1", "cp1252"):
    try:
        df = pd.read_csv(CSV_PATH, encoding=enc)
        break
    except UnicodeDecodeError:
        continue
```

#### Timestamp Normalization
- Loader generates tz-naive UTC timestamps
- Dashboard ensures consistency with `dt.tz_localize(None)`
- Cutoff uses `datetime.now(timezone.utc).replace(tzinfo=None)`

#### Column Mapping
| CIC-IDS Column | Dashboard Column | Transformation |
|----------------|------------------|----------------|
| `Label` | `attack_type` | Lowercase, replace spaces |
| Flow features | `confidence` | Normalized packet counts |
| Attack pattern | `url` | Pattern-based mapping |
| Attack pattern | `status_code` | 401/403/404/500 for attacks |
| Attack pattern | `rules` | Rule string generation |
| Confidence | `level` | ALERT (≥0.75) or WATCH |
| Generated | `timestamp` | Synthetic, 24h spread |
| Generated | `ip` | Synthetic, pattern-based |

### Dataset Statistics
- **File**: `data/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`
- **Size**: 73.34 MB
- **Total flows**: 286,467
- **Threats extracted**: 158,930 (PortScan attacks)
- **Time range**: Last 24 hours (synthetic)
- **Unique IPs**: 19 attacker IPs (203.0.113.1-19)

### Testing
- ✅ Loader test: 158,930 rows processed successfully
- ✅ Dashboard startup: No errors
- ✅ Data display: All charts populated
- ✅ Timezone handling: No comparison errors
- ✅ Encoding: UTF-8 loaded successfully

### Known Limitations
1. All threats classified as WATCH (confidence < 0.75)
2. Single attack type (PortScan only in this CSV)
3. Synthetic timestamps (CIC-IDS lacks real timestamps)
4. Synthetic IPs (CIC-IDS is anonymized)

### Future Enhancements
- [ ] Multi-file concatenation for diverse attack types
- [ ] Confidence threshold tuning for more ALERTs
- [ ] Real timestamp extraction if available
- [ ] More sophisticated IP generation
- [ ] Deduplication logic for multi-file loads

### Commit
```
5575d7f - fix(data): connect CIC-IDS CSVs, robust CSV loader, parse timestamps UTC, map required fields
```

### Files Modified
- `dashboard/cicids_loader.py` (new, 235 lines)
- `dashboard/dashboard_app.py` (modified, 20 lines)
