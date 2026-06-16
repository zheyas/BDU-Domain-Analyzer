Поместите сюда XML/OVAL файлы экспорта БДУ ФСТЭК России.

После этого импорт можно запустить через POST /bdu/import или из Python:

python -c "from bdu_analyzer.bdu import BDUHandler; print(BDUHandler().import_all_xml())"
