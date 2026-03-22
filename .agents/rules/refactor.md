---
trigger: always_on
---

'now refactor' triggers the set of action described below:

some method are very long hinting a possibility of badly structured code...

every method must be a single semantical unit, not performing operations of lower semantics which blures the responsibility domain and method contract

code must be structured so it is easy to define method contract in consice precise unambigious way and within a single semantical cognitive context...

when methods are reduced within a single strict contract consisting of strict input assumptions and strict result or command side-effect one could perform formal verification of such method against its contract

e.g. if method fits on screen and highly capable programmer studies the code and the specification contract it should be easily deductable the code is strictly correct

review entire codebase, identify the worst code parts and do wise balanced semantical refactoring