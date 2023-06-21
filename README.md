# Динамический анализатор сложности подмножеств формальных языков

Динамический анализатор осуществляет структурированный фаззинг в совокупности со статическим анализом для поиска уязвимостей регулярных выражений и регулярных образцов.

## Установка
В соответствии с командами ниже программа может быть установлена в ОС Linux.
`{project_root_directory}` — корневая директория проекта.
```
cd {project_root_directory}
sudo apt-get install cmake nodejs python3-pip g++
pip install -r requirements.txt
cd {project_root_directory}/static_analyzer
mkdir build
cd build
cmake ../.
cmake --build .
```

## Синтаксис ввода
```
Usage: main.py [-h] [-e EXAMPLE] [-v] [-t TIMEOUT] [-r RADIUS] [-p] [-g] [-d DEPTH] [-f] value

Dynamic complexity analysis of regular expressions and re-patterns

Positional arguments:
  value                 value to analyze

Options:
  -h, --help            show this help message and exit
  -e EXAMPLE, --example EXAMPLE
                        the path to the test file
  -v, --visualize       whether to visualize pumping dependencies
  -t TIMEOUT, --timeout TIMEOUT
                        the timeout for matching
  -r RADIUS, --radius RADIUS
                        the max radius for neighborhood extension
  -p, --pattern         re-pattern mode
  -g, --genetic         whether to use genetic algorithms for analysis
  -d DEPTH, --depth DEPTH
                        the limit for recursive opening of regexes
  -f, --first           whether to show the first vulnerability
```

## Примеры запуска

### Замечания
1. Программный модуль предназначен для анализа регулярных выражений и образцов с ограниченным алфавитом — [A-z].
2. Программный модуль основан на динамическом алгоритме (также есть возможность использования генетических алгоритмов), поэтому выходные данные не детерминированы.
3. По умолчанию ограничение времени для каждой подпроцедуры — 2 секунды.
4. Для получения первой найденной уязвимости необходимо использовать соответствующий флаг `-f`.
5. Для визуализации графиков предположительных атак необходимо использовать флаг `-v`.
6. В модуле релизовано обучение нестрирающих образцов, для использования которого на уязвимых строках нужно перейти в директорию `{project_root_directory}\src\patterns_learning`.

### Стратегия 1
На вход программе может быть подано одно регулярное выражение, заключенное в кавычки. Регулярное выражение должно соответствовать классическому синтаксису, где разрешено использование `"|", "*", "(...)"`, а также может включать в себя обратные ссылки, соответствующие переменным в регулярных образцах (при выборе режима образцов `-p` необходимо следить за отсутствием вложенности переменных) или расширенным регулярным выражениям (в стандартном режиме допускается вложенность переменных).

#### Определение
Пусть `"(a*)b\\1"` — расширенное регулярное выражение, тогда ему соответствует язык $a^n b a^n$, где `(a*)` -- группа со значением `a*`, `\\1` — объявление переменной, соответствующей первой группе, то есть `(a*)`.

#### Ввод:
```
python3 main.py "a(a*)\\1" -p -f
```
#### Вывод:
```
Found: polynomial
Pumping pattern:
a[Y2]b, [Y2] = (aa)*
```

### Стратегия 2
Вместо одной строки, соответствующей регулярному выражению, можно использовать индекс примера из файла `{filename.txt}` (начиная с нуля).

#### Ввод:
```
python3 main.py 0 -p -e test_pattern.txt
```
#### Вывод:
```
Example: (a|a)*
Found: exponential
Pumping pattern:
[X0]p, [X0] = (a|a)*
```

Чтобы запустить все тесты нужно использовать индекс `-1`. Пример для режима обработки образцов.
#### Ввод:
```
python3 main.py -1 -p -e test_pattern.txt
```
#### Вывод:
```
Example: (a|a)*
Found: exponential
Pumping pattern:
[X0]f, [X0] = (a|a)*

Example: (a*)aa(\1)*dabaa
Found: polynomial
Pumping pattern:
[Y2]dabaai, [Y2] = (aaaaaa)*

Example: (a|a)*aaab(cd|s|q)*a
Found: exponential
Pumping pattern:
[X0]aaabas, [X0] = (a|a)*

Example: ((ba)*)aaa(ab)*a\1bab
No ambiguity found

Example: (c|bb|d)*aaa(ba)*b
No ambiguity found

Example: (dddd|db)*d(bd)*ab*
Found: polynomial
Pumping pattern:
[Y2]ag, [Y2] = d(bdbd)*

Example: ab(c*)dcb(c*)\1\2(a)*
Found: polynomial
Pumping pattern:
ab[Y1]dcb[Y2][Y0]g, [Y0] = (c)*, [Y1] = (c)*, [Y2] = (ccc)*
abcccdcb[Y2]g, [Y2] = (cccc)*
ab[Y0]dcb[Y2]j, [Y0] = (c)*, [Y2] = (c)*

Example: (a*)aaaa\1
Found: polynomial
Pumping pattern:
[Y2]l, [Y2] = (aaaa)*

Example: a(a*)(b|a*)a\1a\2
Found: polynomial
Pumping pattern:
a[Y2]a[Y0]a[Y1]q, [Y0] = (a)*, [Y1] = (a)*, [Y2] = (a)*
a[Y2]aaw, [Y2] = (aa)*
a[Y2]a[Y0]v, [Y0] = (a)*, [Y2] = (aa)*
a[Y2]e, [Y2] = (aaaa)*
a[Y2]t, [Y2] = (aaa)*
a[Y0][Y1]a[Y2]h, [Y0] = (a)*, [Y1] = (a)*, [Y2] = (aa)*

Example: ((b|a)*)bd(b*)\1bbb\3
Found: polynomial
Pumping pattern:
[Y1]bd[Y2]bbb[Y0]m, [Y0] = (b)*, [Y1] = (b)*, [Y2] = (bbb)*
bbbbbbd[Y2]u, [Y2] = (bbbbbb)*
[Y0]bd[Y2]j, [Y0] = (b)*, [Y2] = (bbb)*

Example: (a*b*)aaaaab*b\1a
Found: polynomial
Pumping pattern:
[Y1]aaaaa[Y2]al, [Y1] = (b)*, [Y2] = (bb)*
```
#### Ввод:
```
python3 main.py -1 -e test_regex.txt
```
#### Вывод:
```
Example: (a|a)*
Found: exponential
Pumping pattern:
[X0]z, [X0] = (a|a)*

Example: (a*)aa(\1)*dabaa
Found: polynomial
Pumping pattern:
[Y2]dabaam, [Y2] = (aa)*

Example: ((aaa)*)*bsma(d|a)
Found: exponential
Pumping pattern:
[X0]j, [X0] = ((aaa)*)*bsma(d|a)
[X1]bsmado, [X1] = ((aaa)*)*

Example: msn((ba)*)aaa(ab)*a\1
Found: polynomial
Pumping pattern:
msn[Y1]aaa[Y2]b, [Y1] = (bb)*bbba, [Y2] = (aba)*

Example: ddddab(a*b*)aaaaab*b\1
Found: polynomial
Pumping pattern:
ddddab[Y1]aaaaa[Y2]w, [Y1] = (bb)*, [Y2] = (bb)*

Example: cd(ab|a)*ab(ab)*
Found: polynomial
Pumping pattern:
[X0]x, [X0] = cd(ab|a)*ab(ab)*
cd[Y3]r, [Y3] = (ab)*

Example: (ab)*(ab|a)*aaaab(ab)*
Found: polynomial
Pumping pattern:
[X0]r, [X0] = (ab)*(ab|a)*aaaab(ab)*
[Y3]aaaabp, [Y3] = (ab)*
[Y6]v, [Y6] = (ab)*

Example: (ab|a)*ab(\1)*bb
Found: polynomial
Pumping pattern:
[Y2]bbz, [Y2] = (ab)*

Example: (ab(a*)aaa)*ab(ab)*bb\1*
No ambiguity found

Example: (abbb(b*))b*\\2b*ddba"
Found: polynomial
Pumping pattern:
[X0]o, [X0] = abbb(b*)b*
abbb[Y3][Y1]ddbaz, [Y1] = (b)*, [Y3] = (b)*
abbb[Y6]ddbad, [Y6] = (bb)*
abbb[Y12]ddbad, [Y12] = (bbb)*
abbbbb[Y15]ddbaj, [Y15] = (bbb)*
```