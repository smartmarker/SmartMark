
#######################SMARTMARK args################################
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('-i', '--input', required=True, type = str, help = 'input CFG json file')
parser.add_argument('-W', '--WRO', required=True, type = str, help = 'input WRO file')
parser.add_argument('-H', '--hashmark', required=True, type=str, help = 'input hashmark file')
parser.add_argument('-o', '--watermark', required=True, type=str, help = 'output watermark file')
args = parser.parse_args()
#######################SMARTMARK args################################

import re
import logging
import ast
import json
from Crypto.Hash import keccak


##### fineBlock: find the area of each block from the CFG json file
def findBlock(line, f):
    while 'offset' not in line:
        line = f.readline()

        if not line:
            return -1

    line = re.split('\:', line)[1]
    line = re.split('\,', line)[0]
    offset = int(line)

    ## If found the CFG block area, return the offset of the block
    return offset

##### findBlockBytes: find the bytecode of the corresponding CFG block
def findBlockBytes(line, f):
    while 'parsedOpcodes' not in line:
        line = f.readline()

    line = re.split('\"', line)[3]

    return line


## Mapping opcode to byte value
opMap = {'STOP':'00', 'ADD':'01', 'MUL':'02', 'SUB':'03', 'DIV':'04', 'SDIV':'05', 'MOD':'06', 'SMOD':'07', 'ADDMOD':'08', 'MULMOD':'09', 'EXP':'0a', 'SIGNEXTEND':'0b', 
         'LT':'10', 'GT':'11', 'SLT':'12', 'SGT':'13', 'EQ':'14', 'ISZERO':'15', 'AND':'16', 'OR':'17', 'XOR':'18', 'NOT':'19', 'BYTE':'1a', 'SHL':'1b', 'SHR':'1c', 'SAR':'1d', 'SHA3':'20',
         'ADDRESS':'30', 'BALANCE':'31', 'ORIGIN':'32', 'CALLER':'33', 'CALLVALUE':'34', 'CALLDATALOAD':'35', 'CALLDATASIZE':'36', 'CALLDATACOPY':'37', 'CODESIZE':'38', 'CODECOPY':'39', 'GASPRICE':'3a', 'EXTCODESIZE':'3b', 'EXTCODECOPY':'3c', 'RETURNDATASIZE':'3d', 'RETURNDATACOPY':'3e', 'EXTCODEHASH':'3f', 'BLOCKHASH':'40', 'COINBASE':'41', 'TIMESTAMP':'42', 'NUMBER':'43', 'DIFFICULTY':'44', 'GASLIMIT':'45', 'CHAINID':'46', 'SELFBALANCE':'47', 'BASEFEE':'48',
         'POP':'50', 'MLOAD':'51', 'MSTORE':'52', 'MSTORE8':'53', 'SLOAD':'54', 'SSTORE':'55', 'JUMP':'56', 'JUMPI':'57', 'PC':'58', 'MSIZE':'59', 'GAS':'5a', 'JUMPDEST':'5b',
         'PUSH1':'60', 'PUSH2':'61', 'PUSH3':'62', 'PUSH4':'63', 'PUSH5':'64', 'PUSH6':'65', 'PUSH7':'66', 'PUSH8':'67', 'PUSH9':'68', 'PUSH10':'69', 'PUSH11':'6a', 'PUSH12':'6b', 'PUSH13':'6c', 'PUSH14':'6d', 'PUSH15':'6e', 'PUSH16':'6f', 'PUSH17':'70', 'PUSH18':'71', 'PUSH19':'72', 'PUSH20':'73', 'PUSH21':'74', 'PUSH22':'75', 'PUSH23':'76', 'PUSH24':'77', 'PUSH25':'78', 'PUSH26':'79', 'PUSH27':'7a', 'PUSH28':'7b', 'PUSH29':'7c', 'PUSH30':'7d', 'PUSH31':'7e', 'PUSH32':'7f',
         'DUP1':'80', 'DUP2':'81', 'DUP3':'82', 'DUP4':'83', 'DUP5':'84', 'DUP6':'85', 'DUP7':'86', 'DUP8':'87', 'DUP9':'88', 'DUP10':'89', 'DUP11':'8a', 'DUP12':'8b', 'DUP13':'8c', 'DUP14':'8d', 'DUP15':'8e', 'DUP16':'8f',
         'SWAP1':'90', 'SWAP2':'91', 'SWAP3':'92', 'SWAP4':'93', 'SWAP5':'94', 'SWAP6':'95', 'SWAP7':'96', 'SWAP8':'97', 'SWAP9':'98', 'SWAP10':'99', 'SWAP11':'9a', 'SWAP12':'9b', 'SWAP13':'9c', 'SWAP14':'9d', 'SWAP15':'9e', 'SWAP16':'9f',
         'LOG0':'a0', 'LOG1':'a1', 'LOG2':'a2', 'LOG3':'a3', 'LOG4':'a4', 'PUSH':'b0', 'DUP':'b1', 'SWAP':'b2', 'CREATE':'f0', 'CALL':'f1', 'CALLCODE':'f2', 'RETURN':'f3', 'DELEGATECALL':'f4', 'CREATE2':'f5', 'STATICCALL':'fa', 'REVERT':'fd', 'INVALID':'fe', 'SELFDESTRUCT':'ff'}

## Mapping opcode byte value to gas cost
costMap = {'00':0, '01':3, '02':5, '03':3, '04':5, '05':5, '06':5, '07':5, '08':8, '09':8, '0a':10, '0b':5, 
 '10':3, '11':3, '12':3, '13':3, '14':3, '15':3, '16':3, '17':3, '18':3, '19':3, '1a':3, '1b':3, '1c':3, '1d':3, 
 '20':30, '30':2, '31':100, '32':2, '33':2, '34':2, '35':3, '36':2, '37':3, '38':2, '39':3, '3a':2, '3b':100, '3c':103, '3d':2, '3e':3, '3f':100, '40':20, 
 '41':2, '42':2, '43':2, '44':2, '45':2, '46':2, '47':2, '48':2, '50':2, '51':3, '52':3, '53':3, '54':100, '55':100, 
 '56':8, '57':10, '58':2, '59':2, '5a':2, '5b':1, 
 '60':3, '61':3, '62':3, '63':3, '64':3, '65':3, '66':3, '67':3, '68':3, '69':3, '6a':3, '6b':3, '6c':3, '6d':3, '6e':3, '6f':3, '70':3, '71':3, '72':3, '73':3, '74':3, '75':3, '76':3, '77':3, '78':3, '79':3, '7a':3, '7b':3, '7c':3, '7d':3, '7e':3, '7f':3, 
 '80':3, '81':3, '82':3, '83':3, '84':3, '85':3, '86':3, '87':3, '88':3, '89':3, '8a':3, '8b':3, '8c':3, '8d':3, '8e':3, '8f':3, '90':3, '91':3, '92':3, '93':3, '94':3, '95':3, '96':3, '97':3, '98':3, '99':3, '9a':3, '9b':3, '9c':3, '9d':3, '9e':3, '9f':3, 
 'a0':375, 'a1':375, 'a2':375, 'a3':375, 'a4':375, 'b0':10, 'b1':10, 'b2':10, 'f0':3200, 'f1':100, 'f2':100, 'f3':10, 'f4':100, 'f5':3200, 'fa':100, 'fd':10, 'fe':0, 'ff':5000}   



input_CFG = args.input
input_WRO = args.WRO
input_hashmark = args.hashmark
output_watermark = args.watermark  


with open(input_CFG) as f:

    ## blockBYtes: store bytecode of each CFG block of this contract as a list
    blockBytes = []
    ## watermarkable_blockBytes: List to store bytecode of each CFG block (only watermarkable code region) of a single contract
    watermarkable_bytestreams = []
    
    line = f.readline()
    
    ######################create watermarkable zone######################################
    while line:
        
        ##### fineBlock: find the area of each block from the CFG json file
        cur_offset = findBlock(line, f)
        
        if cur_offset == -1:
            break
        
        line = f.readline()
        line = f.readline()
        ## use only function CFG blocks except dispatcher blocks
        if 'common' in line:
            
            ##### findBlockBytes: find the byte code of the corresponding CFG block
            cur_parsedOpcodes = findBlockBytes(line, f)
            
            ## A regular expression that splits opcode and operand from the bycode of each CFG block
            eachInst = re.compile("([0-9]{1,5})(: )([A-Z]{1,14})([0-9]{1,2})*( )*(0x)*([0-9a-f]{1,64})*")
            result = eachInst.finditer(cur_parsedOpcodes)
            
            ## a string variable to store the bytecode of a single CFG block.
            blockByte = str()
            
            for iter,r in enumerate(result):
                if r[4] is None:
                    opcode = r[3]
                else:
                    opcode = r[3]+r[4]
                
                opcode = opMap[opcode]
                blockByte += opcode        
            
            ## store this CFG block in list if the corresponding block is non-redundant
            if blockByte not in blockBytes:
                blockBytes.append(blockByte)
                                                  
    ######################create watermarkable zone######################################
    

## read the (1) watermark related information (i.e., CFG ID, hashAlgorithm ID, watermark length/numer,etc.), 
# (2) CFG block hash + watermark byte nibble offset list,
# (3) opcode group list
with open(input_WRO) as f:
    WRO = f.readlines()            
f.close()

WRO_str = "".join(WRO)
WRO = [line.strip() for line in WRO]
    
## read the (1) watermark related information
watermark_info = WRO[0]
CFGGeneratorID = watermark_info[0:4]
hashAlgoID = watermark_info[4:8]
lenWatermark = int(watermark_info[8:12])
numWatermark = int(watermark_info[12:16])

input_watermarks = [watermark_info[o:o+lenWatermark*2] for o in range(16, len(watermark_info), lenWatermark*2)]

## read the (2) CFG block hash + watermark byte nibble offset list
WMs = WRO[1]
blockHashs = [WMs[o:o+8] for o in range(0, len(WMs), 16)]
byteIndexes = [WMs[o:o+8] for o in range(8, len(WMs), 16)]

## read the (3) opcode group list
opGroupList = WRO[2]
opGroupList = ast.literal_eval(opGroupList)

######################create watermarkable bytestream for each CFG block and store its hash######################################
blockByteNHashs = []

for blockByte in blockBytes:
    
    base_blockByte = ['z' for i in range(len(blockByte))]

    for opGroup in opGroupList:
        byteLocs = list(re.finditer(opGroup, blockByte))
        if len(byteLocs) > 0:
            for byteLoc in byteLocs:
                for i in range(byteLoc.start(), byteLoc.end()):
                    base_blockByte[i]=blockByte[i]                       
        
    watermarkable_bytestream = "".join(f for f in base_blockByte if f != 'z')
    if len(watermarkable_bytestream)>=2 and watermarkable_bytestream not in watermarkable_bytestreams:
        watermarkable_bytestreams.append(watermarkable_bytestream)

        ## generate the node hash value (keccak-256) and store it with the corresponding bytecode
        hash = keccak.new(digest_bits=256)
        hash.update(watermarkable_bytestream.encode('utf-8'))
        hash = hash.hexdigest()[:8]
            
        byteNHash = {"bytecode":watermarkable_bytestream, "blockHash":hash}
        json.dumps(byteNHash)
        blockByteNHashs.append(byteNHash) 

        
for blockByte in blockBytes:
        
    base_blockByte = ['z' for i in range(len(blockByte))]

    for opGroup in opGroupList:
        byteLocs = list(re.finditer(opGroup, blockByte))
        if len(byteLocs) > 0:
            for byteLoc in byteLocs:
                for i in range(byteLoc.start(), byteLoc.end()):
                    base_blockByte[i]=blockByte[i]                   
    
    watermarkable_bytestream = "".join(f for f in base_blockByte if f != 'z')
    if len(watermarkable_bytestream)>=2 and watermarkable_bytestream not in watermarkable_bytestreams:
        watermarkable_bytestreams.append(watermarkable_bytestream)
######################create watermarkable bytestream for each CFG block######################################


with open(input_hashmark) as f:
    input_hashMark = f.readline()
f.close()

hashmark = keccak.new(digest_bits=256)
hashmark.update("".join(WRO_str).encode('utf-8'))
if input_hashMark != hashmark.hexdigest():
    logging.error("[NOT VALID] this WRO cannot be verified by given hashmark")


watermarks = []
watermark = str()
for (cnt, blockHash) in enumerate(blockHashs, start=0):
    found_watermark = False
    for data in blockByteNHashs:
        if data["blockHash"] == blockHash:
            found_watermark = True
            byteIndex = int(byteIndexes[cnt])
            watermark += data["bytecode"][byteIndex]+data["bytecode"][byteIndex+1]
            break
    if found_watermark==False:
        watermark += "  "
    if ((cnt+1)%lenWatermark)==0:
        watermarks.append(watermark)
        watermark = str()

fa = open(output_watermark,"a")
watermark_verified = False
for i in range(0,len(input_watermarks)):
    if input_watermarks[i] == watermarks[i]:
        watermark_verified = True
        this_watermark = "verified"
    else:
        this_watermark = "not verified"
    fa.write(input_watermarks[i]+"\t"+watermarks[i]+"\t"+this_watermark+"\n")
fa.close()

if watermark_verified == False:
    logging.error("[NOT VALID] this contract cannot be verified by given WRO")
    

