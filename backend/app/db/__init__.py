"""Database access: two separate MySQL accounts with two separate engines.

* askq_app    -> ORM sessions for ASKQ's own data (auth lookups, askq_system writes)
* askq_reader -> read-only connections for organisational data (future NL-to-SQL
                 execution). Never used for application metadata or writes.
"""
