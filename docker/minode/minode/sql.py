"""Inventory implementation using sqlite"""

import base64
import logging
import os
import sqlite3
import threading
import time

from . import shared, structure

sqlite3.threadsafety = 3


class Inventory():
    """sqlite inventory"""
    def __init__(self):
        self._lock = threading.Lock()
        self._deleted = 0
        self._last = {}
        self._pending = set()
        self._db = sqlite3.connect(
            os.path.join(shared.data_directory, 'objects.dat'),
            check_same_thread=False
        )
        self._db.executescript("""
        BEGIN;
        CREATE TABLE IF NOT EXISTS status
        (key text, value integer, UNIQUE(key) ON CONFLICT REPLACE);
        INSERT INTO status VALUES ('version', 1);
        CREATE TABLE IF NOT EXISTS objects
        (vector unique, expires integer, type integer, version integer,
        stream integer, tag, data, offset integer);
        COMMIT;
        """)
        self.rowid = len(self) or None
        try:
            self.lastvacuumtime = self._db.execute(
                "SELECT value FROM status WHERE key='lastvacuumtime'"
            ).fetchone()[0]
        except TypeError:
            self.lastvacuumtime = int(time.time())
            self._db.execute(
                "INSERT INTO status VALUES ('lastvacuumtime', ?)",
                (self.lastvacuumtime,)
            )
        self._db.commit()
        self._db.row_factory = self.__object

    @staticmethod
    def __object(cursor, row):
        if len(cursor.description) != 8:
            return row
        vector, expires, obj_type, version, stream, tag, data, offset = row
        return structure.Object(
            expires, obj_type, version, stream,
            data=data, offset=offset, tag=tag, vector=vector)

    def check(self, *vectors):
        """Remove given vectors from pending"""
        with self._lock:
            for vector in vectors:
                self._pending.discard(vector)

    def cleanup(self):
        """Remove expired objects"""
        if len(self._pending) > 100:
            logging.info(
                'Not cleaning up, %s objects pending', len(self._pending))
            return
        for vector in set(self._last):
            if self._last[vector].is_expired():
                logging.debug(
                    'Deleted expired object: %s',
                    base64.b16encode(vector).decode())
                with self._lock:
                    del self._last[vector]
        if len(self._last) > 1000:
            self.flush()
            return
        with self._lock:
            now = int(time.time())
            cur = self._db.execute(
                'DELETE FROM objects WHERE expires < ?', (now - 3 * 3600,))
            self._db.commit()
            self._deleted += cur.rowcount
            (logging.info if self._pending else logging.debug)(
                'Deleted %s expired objects, %s pending',
                cur.rowcount, len(self._pending))
            # conditional vacuum and validity check (TODO)
            # every 24 hours or after deleting a lot of items
            if self._deleted > 10000 or self.lastvacuumtime < now - 86400:
                logging.info('Doing VACUUM for objects')
                cur.execute('VACUUM')
                cur.execute(
                    "INSERT INTO status VALUES ('lastvacuumtime', ?)", (now,))
                self._db.commit()
                self._deleted = 0
                self.lastvacuumtime = now

    def flush(self):
        """Write cached objects to the database"""
        with self._lock:
            cur = self._db.executemany(
                'INSERT INTO objects VALUES (?,?,?,?,?,?,?,?)',
                ((obj.vector, obj.expires_time, obj.object_type,
                  obj.version, obj.stream_number, obj.tag, obj.data,
                  obj.offset) for obj in self._last.values()))
            self._db.commit()
            self.rowid = cur.lastrowid
            self._last = {}

    def filter(self, stream=None, object_type=None, tag=None):
        """Generator of objects with the given parameters"""
        def fits(obj):
            if stream and obj.stream_number != stream:
                return False
            if object_type is not None and obj.object_type != object_type:
                return False
            if tag and obj.tag != tag:
                return False
            return True

        yield from filter(fits, self._last.values())

        clauses = []
        if stream:
            clauses.append(('stream = ?', stream))
        if object_type is not None:
            clauses.append(('type = ?', object_type))
        if tag:
            clauses.append(('tag = ?', tag))

        clauses, params = zip(*clauses)

        yield from self._db.execute(
            'SELECT * FROM objects WHERE '  # nosec B608
            + ' AND '.join(clauses), params)

    def select(self, vectors):
        """Select new vectors from the given set"""
        chunk_size = 999
        with self._lock:
            vectors.difference_update(self._last)
            keys = tuple(vectors)
            for i in range(0, len(vectors), chunk_size):
                chunk = keys[i:i+chunk_size]
                cur = self._db.execute(
                    'SELECT vector FROM objects WHERE vector IN'  # nosec B608
                    ' ({})'.format(','.join('?' * len(chunk))),
                    chunk)
                for v, in cur:
                    vectors.remove(v)
            self._pending.update(vectors)
        return vectors

    def biginv_chunks(self, chunk_size=10000, stream=None):
        """Generator of vector lists for making the biginv"""
        if stream is None:
            stream = shared.stream
        now = int(time.time())
        cur = self._db.execute(
            'SELECT vector FROM objects WHERE expires > ? AND stream = ?'
            ' ORDER BY random()', (now, stream)
        )
        cur.arraysize = chunk_size
        while True:
            vectors = cur.fetchmany()
            if not vectors:
                # TODO: append to the last short result,
                # check that _last is shorter than the chunk_size
                # (should be < 1000)
                if self._last:
                    yield [
                        obj.vector for obj in self._last.values()
                        if obj.stream_number == stream
                        and obj.expires_time > now]
                return
            yield [v for v, in vectors]

    def get(self, vector, default=None):
        try:
            return self[vector]
        except KeyError:
            return default

    def keys(self):
        yield from self._last
        for vector, in self._db.execute('SELECT vector FROM objects'):
            yield vector

    def values(self):
        yield from self._last.values()
        yield from self._db.execute('SELECT * FROM objects')

    def popitem(self):
        try:
            return self._last.popitem()
        except KeyError:
            pass
        if not self.rowid:
            raise KeyError('empty')
        cur = self._db.execute(
            'SELECT vector FROM objects WHERE ROWID = ?', (self.rowid,))
        vector = cur.fetchone()[0]
        obj = self.get(vector)
        del self[vector]
        return (vector, obj)

    def __contains__(self, vector):
        if vector in self._last:
            return True
        return self._db.execute(
            'SELECT vector FROM objects WHERE vector = ?', (vector,)
        ).fetchone() is not None

    def __getitem__(self, vector):
        try:
            return self._last[vector]
        except KeyError:
            pass
        item = self._db.execute(
            'SELECT * FROM objects WHERE vector = ?', (vector,)).fetchone()
        if item is None:
            raise KeyError(vector)
        return item

    def __delitem__(self, vector):
        try:
            del self._last[vector]
            return
        except KeyError:
            pass
        with self._lock:  # KeyError
            self._db.execute('DELETE FROM objects WHERE vector = ?', (vector,))
            self._db.commit()
            self.rowid = len(self)

    def __setitem__(self, vector, obj):
        if vector in self:
            return
        with self._lock:
            self._last[vector] = obj

    def __bool__(self):
        if self._last:
            return True
        return self._db.execute(
            'SELECT vector from objects LIMIT 1').fetchone() is not None

    def __len__(self):
        cur = self._db.execute('SELECT count(*) FROM objects')
        return cur.fetchone()[0] + len(self._last)

    def __del__(self):
        self.flush()
        self._db.close()
