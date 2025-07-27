Problems:

3. OpenAPI spec maintainance sucks
   - SOLUTION: Split into sub-modules that are bundled alongside their respective routes.

4. Code is monolithic
   - SOLUTION: Split code into modules and files for each route.

5. A lot of repeated code
   - Getting a pool connection
   - Requring a given consent
   - Mapping row(s)
   - SOLUTION: Move code to helpers where it makes sense

6. Formatting SQL is a pain

7. Lots of state.blah
   - SOLUTION: explode state

8. No syntax highlighting for SQL
