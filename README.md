# ERegexFuzzer

Structured fuzzing of extended regex and regular patterns using multipatterns.

## Installing
```
cd project_root_directory
sudo apt-get install cmake nodejs python3-pip g++
pip install -r requirements.txt
cd {project_root_directory}/static_analyzer
mkdir build
cd build
cmake ../.
cmake --build .
```

## Fuzzing
```
usage: main.py [-h] [-v VISUALIZE] [-t TIMEOUT] [-r RADIUS] [-p] [-f] value

Dynamic complexity analysis of regular expressions and re-patterns

positional arguments:
  value                 value to analyze

options:
  -h, --help            show this help message and exit
  -v VISUALIZE, --visualize VISUALIZE
                        path to file for structure visualization
  -t TIMEOUT, --timeout TIMEOUT
                        timeout for matching
  -r RADIUS, --radius RADIUS
                        max radius for neighborhood extension
  -p, --pattern         re-pattern mode
  -f, --first           whether to show first vulnerability
```

## Example
Input:
```
python3 main.py "a(a*)\\1" -p -f
```
Output:
```
Found: polynomial
Pumping pattern: a x1 x1 m, x1 = a*
```