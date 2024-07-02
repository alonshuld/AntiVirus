# Anti Virus

This project gets a directory to scan and a binary file that represents the virus.
The program will scan through each file in the directory and try to search for the virus in each file.

There is 2 scanning options:
* Normal scan. scans the file from the beggining to the end
* Quick scan. scans the first 20% of the file, then the last 20% and then the whole file

The output is which file is infected and a log file will be created in the directory

## Usage

```bash
virusScan.exe <dir> <file>
```

## License

[MIT](https://choosealicense.com/licenses/mit/)
