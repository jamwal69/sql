"""
Database migration script to upgrade to enhanced memory system
Run this to add sentiment and enhanced memory columns
"""

import sqlite3
import os


def migrate_database(db_path="customer_memory.db"):
    """Migrate existing database to new schema"""
    
    print(f"🔄 Migrating database: {db_path}")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Check if sentiment column exists
        cursor.execute("PRAGMA table_info(conversations)")
        columns = [col[1] for col in cursor.fetchall()]
        
        if 'sentiment' not in columns:
            print("  ➕ Adding 'sentiment' column to conversations table...")
            cursor.execute("""
                ALTER TABLE conversations 
                ADD COLUMN sentiment TEXT DEFAULT 'neutral'
            """)
            print("  ✅ Added sentiment column")
        else:
            print("  ✓ Sentiment column already exists")
        
        # Check customer_context table structure
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name='customer_context'
        """)
        
        if cursor.fetchone():
            cursor.execute("PRAGMA table_info(customer_context)")
            context_columns = [col[1] for col in cursor.fetchall()]
            
            if 'loyalty_tier' not in context_columns:
                print("  ➕ Adding 'loyalty_tier' column to customer_context...")
                cursor.execute("""
                    ALTER TABLE customer_context 
                    ADD COLUMN loyalty_tier TEXT
                """)
            
            if 'sentiment_history' not in context_columns:
                print("  ➕ Adding 'sentiment_history' column to customer_context...")
                cursor.execute("""
                    ALTER TABLE customer_context 
                    ADD COLUMN sentiment_history TEXT
                """)
            
            if 'total_interactions' not in context_columns:
                print("  ➕ Adding 'total_interactions' column to customer_context...")
                cursor.execute("""
                    ALTER TABLE customer_context 
                    ADD COLUMN total_interactions INTEGER DEFAULT 0
                """)
            
            print("  ✅ Updated customer_context table")
        
        # Create support_history table if it doesn't exist
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS support_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                customer_id TEXT NOT NULL,
                issue_date TEXT NOT NULL,
                issue_type TEXT,
                issue_description TEXT,
                resolution TEXT,
                sentiment_before TEXT,
                sentiment_after TEXT,
                agent_notes TEXT
            )
        """)
        print("  ✅ Created/verified support_history table")
        
        conn.commit()
        print("\n✅ Database migration completed successfully!\n")
        
    except Exception as e:
        print(f"\n❌ Migration error: {e}\n")
        conn.rollback()
    finally:
        conn.close()


def recreate_database(db_path="customer_memory.db"):
    """Recreate database from scratch (WARNING: Deletes existing data!)"""
    
    if os.path.exists(db_path):
        backup = db_path + ".backup"
        print(f"📦 Backing up existing database to {backup}")
        import shutil
        shutil.copy(db_path, backup)
        
        print(f"🗑️  Deleting old database...")
        os.remove(db_path)
    
    print(f"🆕 Creating fresh database with new schema...")
    
    # Import and initialize the enhanced memory manager
    from enhanced_agent import EnhancedMemoryManager
    memory = EnhancedMemoryManager(db_path)
    
    print("✅ New database created successfully!\n")


if __name__ == "__main__":
    print("="*70)
    print("DATABASE MIGRATION TOOL")
    print("="*70)
    print("\nOptions:")
    print("1. Migrate existing database (keeps data, adds new columns)")
    print("2. Recreate database (deletes old data, fresh start)")
    print("0. Exit")
    
    choice = input("\nSelect option: ").strip()
    
    if choice == "1":
        migrate_database()
    elif choice == "2":
        confirm = input("\n⚠️  WARNING: This will delete all existing data! Continue? (yes/no): ")
        if confirm.lower() == "yes":
            recreate_database()
        else:
            print("❌ Cancelled")
    else:
        print("👋 Goodbye!")
