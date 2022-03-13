import string
import sqlite3

def rand_str(chars, N):
    import random

    return "".join(random.choice(chars) for _ in range(N))

conn = sqlite3.connect("sidewalk.db")

sql_query = """
    INSERT INTO access_codes (id, code, claimed_by)
    VALUES (NULL, ?, NULL);
"""

code = rand_str(string.ascii_letters + string.digits, 15)

conn.execute(sql_query, (code,))
conn.commit()
