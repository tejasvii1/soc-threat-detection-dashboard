
from log_parser import parse_log_file
from db import init_db, insert_events, get_event_count

LOG_PATH = "logs/auth.log"

def main():
    init_db()
    records, stats = parse_log_file(LOG_PATH)
    print("Parse summary:")
    for key, value in stats.items():
        print(f"  {key}: {value}")
    inserted = insert_events(records)
    print(f"\nInserted {inserted} new events into the database.")
    print(f"Total events in database: {get_event_count()}")
if __name__ == "__main__":
    main()