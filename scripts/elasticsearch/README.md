## These are the queries

1. List/count all functions which use a user-input bpf_helper
2. List/count all maps used in a user-input repository
3. List/count all functions which read from a user-input map in a repository
4. List/count all functions which write to a user-input map in a repository
5. List the function call graph for a user-input function in a repository
6. List/count all functions which have a user-input call_depth in a repository
7. List/count all functions with a user-input value for a chosen user-input field (say startline == 35 etc.)
8. For a input function find all maps which are only read (and not written) across its FCG.
9. For a input function find all maps which are only written (and not read) across its FCG.
10. For a input function find all maps which are read as well as written across its FCG.
11. For a given FCG, for all maps in that FCG, (Identify producer-consumer relation among functions.)

    a. find functions which write to a map, and any of its successor function which reads the same map.

    b. find functions which read a map, and any of its successor function which writes the same map.

12. Create a consolidated explainability for a function, by identifying for a user input function's FCG:

    a. All compatible hookpoints. (this will be a intersection of compatible hook-points for all functions).

    b. All bpf_helpers called through FCG (function call graph).

    c. All human extracted comments. (please think of a good data-structure, which encompasses comments (human, AI, developer) as well as FCG.

13. Avg FCG size for root functions -- should be average computation on results of [5]
