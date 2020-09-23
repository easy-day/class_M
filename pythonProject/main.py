import pefile
import struct
import datetime


def print_info(data_list):
    for data in data_list:
        print(data[0].ljust(20), str(data[1]).ljust(20), data[2].ljust(20))


def dos_header_info(pe):
    print("-" * 30)
    print("[DOS Header]에서 필요한 정보\n")
    dos_header_list = []
    dos_header_list.append(["실제 변수명", "값", "의미"])
    dos_header_list.append(["e_magic", struct.pack('<H', pe.DOS_HEADER.e_magic).decode('utf8'), "DOS Signature"])
    dos_header_list.append(["e_lfanew", hex(pe.DOS_HEADER.e_lfanew), "NT header offset"])

    print_info(dos_header_list)

    print("-" * 30, "\n")


def nt_header_info(pe):
    print("-" * 30)
    print("[NT header]에서 필요한 정보\n")
    nt_header_list = []
    nt_header_list.append(["실제 변수명", "값", "의미"])
    nt_header_list.append(["Signature", struct.pack('<I', pe.NT_HEADERS.Signature).decode('utf8'), "NF Signature"])
    nt_header_list.append(["Machine", hex(pe.FILE_HEADER.Machine), "CPU 별 고유값 (x86 = 0x14c / x64 = 0x8664)"])

    timeStr = '1970-01-01 00:00:00'
    Thistime = datetime.datetime.strptime(timeStr, '%Y-%m-%d %H:%M:%S')
    LastBuildtime = Thistime + datetime.timedelta(seconds=pe.FILE_HEADER.TimeDateStamp)

    nt_header_list.append(["TimeDateStamp", str(LastBuildtime), "파일을 빌드한 시간"])
    nt_header_list.append(["NumberOfSections", pe.FILE_HEADER.NumberOfSections, "Section의 총 개수"])
    nt_header_list.append(["SizeOfOptionalHeader", hex(pe.FILE_HEADER.SizeOfOptionalHeader), "OptionalHeader의 크기"])
    nt_header_list.append(["Characteristics", hex(pe.FILE_HEADER.Characteristics), "이 파일의 속성"])
    nt_header_list.append(
        ["Magic", hex(pe.OPTIONAL_HEADER.Magic), "Optional header를 구분하는 Signature (32bit=10b / 64bit=20b)"])
    nt_header_list.append(["SizeOfCode", hex(pe.OPTIONAL_HEADER.SizeOfCode), "IMAGE_SCN_CNT_CODE 속성을 갖는 섹션들의 총 사이즈 크기"])
    nt_header_list.append(
        ["AddressOfEntryPoint", hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint), "PE 파일이 메모리 로드 후 처음 실행되어야 하는 코드 주소"])
    nt_header_list.append(["ImageBase", hex(pe.OPTIONAL_HEADER.ImageBase), "PE파일이 매핑되는 시작주소"])
    nt_header_list.append(["SectionAlignment", pe.OPTIONAL_HEADER.SectionAlignment, "메모리 상에서의 최소 섹션 단위"])
    nt_header_list.append(["FileAlignment", pe.OPTIONAL_HEADER.FileAlignment, "파일 상에서의 최소 섹션 단위"])

    print_info(nt_header_list)

    print("-" * 30, "\n")


def sections_header_info(pe):
    print("-" * 30)
    print("[sections_info]에서 필요한 정보\n")
    print("\t개념")
    print("Name".ljust(20), "Section 이름을 나타냄")
    print("VirtualAddress".ljust(20), "섹션의 RAV(ImageBase + VA)를 위한 VA 값")
    print("SizeOfRawData".ljust(20), "파일 상에서 섹션이 차지하는 크기")
    print("PointerToRawData".ljust(20), "파일 상에서 섹션이 시작하는 위치")
    print("Characteristics".ljust(20), "섹션의 특징을 나타냄")
    print("".ljust(20),
          "(0x20000000 = excutable, 0x40000000 = readable, 0x80000000 = writeable, 0x00000020 = contains code, 0x00000040 = contains initialized data)")
    print("")

    print("Name".ljust(20), "Virtual Address".ljust(20), "SizeOfRawData".ljust(20),
          "PointerToRawData".ljust(20), "Characteristics".ljust(20))
    for section in pe.sections:
        print(section.Name.decode('utf8').ljust(20), hex(section.VirtualAddress).ljust(20),
              hex(section.SizeOfRawData).ljust(20), hex(section.PointerToRawData).ljust(20),
              hex(section.Characteristics))

    print("-" * 30, "\n")


print("안녕하세요. 직박구리 Team 입니다.")
path = input("PE 구조가 궁금한 파일 경로를 입력해주세요 >> ")
pe = pefile.PE(path)
print("파싱 시작 ...")
dos_header_info(pe)
nt_header_info(pe)
sections_header_info(pe)