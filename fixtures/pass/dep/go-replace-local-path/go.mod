module example.com/a

require example.com/b v1.2.3
replace example.com/c => example.com/c/v2 v2.0.1
replace example.com/d => github.com/fork/d v1.0.0
require example.com/e v0.9.0
go 1.23
