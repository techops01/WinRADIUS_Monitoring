# WinRADIUS_Monitoring

Описание:
В radius_functions.py происходит обработка статусов и других вещей в базе.
analyze_influx.py основной файл с основными вычислениями

Dashboard описание
пропускная способность в «ops/s» (операции/секунду) 

Что необходимо:

1.Windows Server 2019 with NPS enabled and acting as RADIUS Server for some Access Points

2.Configure the NPS logging (NPS -> Accounting -> Logging settings) to save in the format ODBC (Legacy) and "Monthly"

3.Python3 on the Windows Server 2019 

3.Linux host with run InfluxDB (the database) and Grafana (for the dashboard).


Influx и grafana разворачиваем из docker-compose
Для лучшей производительности меняем способ передачи данных в базу данных radius по UDP протоколу. 
 

Качаем Python3 Windows x64, добавим его в Path в установщике
https://www.python.org/ftp/python/3.10.0/python-3.10.0-amd64.exe


Запускаем cmd

pip install --upgrade pip

pip install python-dateutil


cd %PATH to script% (или run.bat)

python analyze_influx.py



Import the Dashboard

Заходим в графану нажимаем + import

(!)Важный момент: чтобы тянулись актуальные данные нужно в influxdb, каждый раз нужно удалять в папке win_radius_analyzer все из папки logs и файл lasttime.тхт на Windows Server 2019



Как можно улучшить скрипт:
добавить поля Accounting-Request, Accounting-Response, Access-Challenge

Конфигурация во config.json
Желательно добавить в планировщик run.bat потому что скрипт раз в месяц отваливается потому что создается новый лог. Альтернатива - создать службу Windows с автоперезапуском


