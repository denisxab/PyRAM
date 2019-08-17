# -*- coding: utf-8 -*-
import ctypes
import psutil
from Check_class import Check_class

"""
Поиск в ОЗУ

Источники:
https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
http://www.cyberforum.ru/python/thread1906241.html
"""

@Check_class(0)
def getpid(procname: str):
    for process in psutil.process_iter():
        if process.name() == procname:
            return process.pid
    raise Exception("Процесс не найден")


class PyRAM:
    """
    PyRAM(Name_Process: None, Address: int, Set_Data: int = None, Sbytes: int = 4)
    Name_Process = Либо название процесса либо Pid
    Address = Точный адрес в памяти, можно получить из Cheat Engine
    Set_Data = Для того чтобы изменить значение на указанное
    Range_address = диапазон поиска,tuple в виде (страт,стоп)
    Mbytes = Длина массива
    """

    @Check_class(0)
    def __init__(self: None, Name_Process: None, Address: None = None, Set_Data: int = None, Range_address: tuple = None, Sbytes: int = 4):

        super(PyRAM, self).__init__()
        #-------------------------------------------------------------------#
        self.PROCESS_VM_READ = 0x0010
        self.PROCESS_VM_WRITE = 0x0020
        self.PROCESS_VM_OPERATION = 0x0008
        self.PAGE_READWRITE = 0x04
        self.OpenProcess = ctypes.windll.kernel32.OpenProcess
        self.CloseHandle = ctypes.windll.kernel32.CloseHandle
        self.ReadProcessMemory = ctypes.windll.kernel32.ReadProcessMemory
        self.WriteProcessMemory = ctypes.windll.kernel32.WriteProcessMemory
        self.VirtualProtectEx = ctypes.windll.kernel32.VirtualProtectEx
        #-------------------------------------------------------------------#

        # Поиск PID
        if isinstance(Name_Process, int):  # Если нужно искать Pid по имени процесса
            self.PID = Name_Process
        elif isinstance(Name_Process, str):  # Если Pid известен
            self.PID = getpid(Name_Process)

        # Преобразвание в нужный формат
        if isinstance(Address, int):
            self.BAddress = Address  # если 0x01
        elif isinstance(Address, str):
            self.BAddress = int(Address, 16)  # если '0x01'

        # Необходимый параметер
        self.process_handle = self.OpenProcess(
            self.PROCESS_VM_READ | self.PROCESS_VM_WRITE | self.PROCESS_VM_OPERATION, 0, self.PID)

        # Запись значения в Адрес
        self.WRM = None if not Set_Data else self.write_process_memory_uint(
            self.process_handle,
            self.BAddress, Set_Data)

        # если нужно пройти по участку памяти
        if Range_address and not Address: 
            self.RRM = []
            for self.x in range(Range_address[0], Range_address[1]):
                self.Ram = self.read_process_memory(
                    self.process_handle, int(hex(self.x), 16), Sbytes)
                if self.Ram:
                    self.RRM.append(self.Ram)

        # Взять значение из точного адреса
        elif not Range_address and Address: 
            self.RRM = self.read_process_memory(
                self.process_handle, self.BAddress, Sbytes)

        self.CloseHandle(self.process_handle)


    def read_process_memory(self: None, handle: int, address: None, bytes: int):
        """
        Делает:
        1) Ищет значение в адрессе ОЗУ
        Надо:
        1) self.process_handle
        2) Адрес в Памяти
        3) Длинна поиска в адрессе памяти
        """
        buffer = ctypes.create_string_buffer(bytes)
        bytesread = ctypes.c_ulong(0)
        if not self.ReadProcessMemory(handle, address, buffer, bytes, ctypes.byref(bytesread)):
            return False

        if buffer.value:
            try:
                return ord(buffer.value), hex(address), buffer.raw
            except Exception:
                return False
        return None


    def write_process_memory_uint(self: None, handle: int, address: int, data: int):
        """
        Делает:
        1) Записавает значение в адресс памяти
        Надо:
        1) self.process_handle
        2) Адрес ОЗУ
        3) Значение
        """
        buffer = ctypes.c_uint(data)
        byteswriten = ctypes.c_ulong(0)
        buffer_size = ctypes.sizeof(buffer)
        old_protect = ctypes.c_ulong(0)
        self.VirtualProtectEx(handle, address, buffer_size,
                              self.PAGE_READWRITE, ctypes.byref(old_protect))

        if not self.WriteProcessMemory(handle, address, ctypes.byref(buffer), buffer_size, ctypes.byref(byteswriten)):
            raise ctypes.WinError()

        self.VirtualProtectEx(handle, address, buffer_size,
                              old_protect.value, ctypes.byref(old_protect))
        return True


if __name__ == '__main__':
    Name_Process = 4588
    Range_address = (0, 100000)
    
    Ram = PyRAM(Name_Process, Range_address=Range_address)
    print(Ram.RRM)  # Значение из ОЗУ
    print(Ram.WRM)  # Отчет о Записи
    print(Ram.PID)  # PID процесса
