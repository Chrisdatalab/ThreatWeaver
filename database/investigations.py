from database.db import get_connection


def create_investigation(title):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO investigations (title)
        VALUES (%s)
        RETURNING id, title, status, created_at, updated_at;
        """,
        (title,)
    )

    investigation = cursor.fetchone()

    conn.commit()

    cursor.close()
    conn.close()

    return investigation