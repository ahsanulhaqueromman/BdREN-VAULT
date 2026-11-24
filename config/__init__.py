# Use PyMySQL as the MySQL driver. It is pure Python, so no C build tools are needed (Linux and Windows).
try:
    import pymysql

    pymysql.install_as_MySQLdb()
except ImportError:  # only matters when DBMS_DB_ENGINE=mysql
    pass
