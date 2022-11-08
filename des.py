#importing library
import math

#global variables declaration
global pt_hexa,pt_bin,pt_bin_ip_box,pt_left,pt_right,pt_right_exp,key_hexa,key_bin,key_bin_pc1,key_left,key_right,key_left_lcs,key_right_lcs,key_lcs,round_key,xor_pt_key_res,s_box_res,straight_p_box_res,xor_Pt_left_straight_p_box_res_res,final_pt,ct

#initial permutation box
def ip_box(pt_bin):
    ip_box_list=[58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7]
    global pt_bin_ip_box
    pt_bin_ip_box=''
    for i in range(64):
        pt_bin_ip_box += pt_bin[ip_box_list[i]-1]
    return pt_bin_ip_box

#64 bit of plaintext after passing through initial permutatin box, splitting into two parts each consisting of 32 bit
def pt_split(pt_bin_ip_box):
    global pt_left
    global pt_right
    pt_left=''
    pt_right=''
    for i in range(32):
        pt_left += pt_bin_ip_box[i]
    for i in range(32,64):
        pt_right += pt_bin_ip_box[i]
    return pt_right

#expansion box
def exp_box(pt_right):
    global pt_right_exp
    pt_right_exp=''
    c1=0
    for i in range(8):
        if(i!=7):
            pt_right_exp += pt_right[c1-1]
            pt_right_exp += pt_right[c1]
            pt_right_exp += pt_right[c1+1]
            pt_right_exp += pt_right[c1+2]
            pt_right_exp += pt_right[c1+3]
            pt_right_exp += pt_right[c1+4]
        if(i==7):
            pt_right_exp += pt_right[c1-1]
            pt_right_exp += pt_right[c1]
            pt_right_exp += pt_right[c1+1]
            pt_right_exp += pt_right[c1+2]
            pt_right_exp += pt_right[c1+3]
            pt_right_exp += pt_right[c1-c1]
        c1+=4
    return pt_right_exp

#pc1 table or parity drop table
def pc1(key_bin):
    global key_bin_pc1
    key_bin_pc1=''
    pc1_list=[57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4]
    for i in range(56):
        key_bin_pc1 += key_bin[pc1_list[i]-1]
    return key_bin_pc1

#56 bit of key after passing through pc1 table(or)parity drop table, splitting into two parts each consisting of 28 bit
def key_split(key_bin_pc1):
    global key_left
    global key_right
    key_left=''
    key_right=''
    for i in range(28):
        key_left += key_bin_pc1[i]
    for i in range(28,56):
        key_right += key_bin_pc1[i]
    return key_left,key_right

#left circular shift
def lcs(key_left,key_right):
    global key_left_lcs
    global key_right_lcs
    global key_lcs
    key_left_lcs=''
    key_right_lcs=''
    key_lcs=''
    for i in range(28):
        if(i!=27):
            key_left_lcs += key_left[i+1]
        if(i==27):
            key_left_lcs += key_left[i-i]
    for i in range(28):
        if(i!=27):
            key_right_lcs += key_right[i+1]
        if(i==27):
            key_right_lcs += key_right[i-i]
    key_lcs= key_left_lcs + key_right_lcs
    return key_lcs

#pc2 table or compression D-box
def pc2(key_lcs):
    pc2_list=[14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32]
    global round_key
    round_key=''
    c2=0
    for i in range(57):
        if i not in pc2_list:
            continue
        if i in pc2_list:
            round_key += key_lcs[pc2_list[c2]-1]
            c2 += 1
    return round_key

#xor operation between plaintext and roundkey
def xor_pt_key(pt_right_exp,round_key):
    global xor_pt_key_res
    xor_pt_key_res=''
    xor_pt_key_res="".join(list(str(int(a)^int(b)) for a,b in zip(pt_right_exp,round_key)))
    return xor_pt_key_res

#8 s-boxes
def s_box(xor_pt_key_res):
    global s_box_res
    s1=[[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],[0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],[4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],[15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]]
    s2=[[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],[3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],[0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],[13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]]
    s3=[[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],[13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],[13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],[1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]]
    s4=[[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],[13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],[10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],[3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]]
    s5=[[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],[14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],[4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],[11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]]
    s6=[[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],[10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],[9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],[4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]]
    s7=[[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],[13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],[1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],[6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]]
    s8=[[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],[1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],[7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],[2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]]
    l1=[]
    c4=0
    for i in range(8):
        sl1=[]
        for j in range(6):
            sl1.append(xor_pt_key_res[c4])
            c4+=1
            if(len(sl1)==6):
                break
        l1.append(sl1)
    l2=[]
    l3=[]
    c5=0
    for i in range(8):
        c6=0
        c7=1
        row_bin=''
        col_bin=''
        for i in range(2):
            row_bin +=str(l1[c5][c6])
            c6+=5
        row_dec=int(row_bin,2)
        l2.append(row_dec)
        for i in range(4):
            col_bin +=str(l1[c5][c7])
            c7+=1
        col_dec=int(col_bin,2)
        l3.append(col_dec)
        c5+=1
    l4=[]
    l4.append(s1[l2[0]][l3[0]])
    l4.append(s2[l2[1]][l3[1]])
    l4.append(s3[l2[2]][l3[2]])
    l4.append(s4[l2[3]][l3[3]])
    l4.append(s5[l2[4]][l3[4]])
    l4.append(s6[l2[5]][l3[5]])
    l4.append(s7[l2[6]][l3[6]])
    l4.append(s8[l2[7]][l3[7]])
    l5=[]
    for i in l4:
        l5.append(bin(int(i)).replace('0b','').zfill(4))
    s_box_res=''
    for i in l5:
        s_box_res +=i
    return s_box_res

#straight p-box or permutation function
def straight_p_box(s_box_res):
    global straight_p_box_res
    straight_p_box_res=''
    straight_p_box_list=[16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25]
    c8=0
    for i in range(1,33):
        if i in straight_p_box_list:
            straight_p_box_res += s_box_res[straight_p_box_list[c8]-1]
            c8 +=1
        if i not in straight_p_box_list:
            c8 +=1
            continue
    return straight_p_box_res

#xor operation between pt_left and straight_p_box_res
def xor_Pt_left_straight_p_box_res(pt_left,straight_p_box_res):
    global xor_Pt_left_straight_p_box_res_res
    xor_Pt_left_straight_p_box_res_res=''
    xor_Pt_left_straight_p_box_res_res="".join(list(str(int(a)^int(b)) for a,b in zip(pt_left,straight_p_box_res)))
    return xor_Pt_left_straight_p_box_res_res

#final permutation box
def fp_box(final_pt):
    fp_box_list =[40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25]
    global ct
    ct=''
    for i in range(64):
        ct += final_pt[fp_box_list[i]-1]
    print("ciphertext:",format(int(ct,2),'x'))
    return ct

if __name__ == "__main__":
    #plaintext in hexadecimal
    pt_hexa='02468aceeca86420'
    print("Plaintext:",pt_hexa)
    #plaintext in binary
    pt_bin=bin(int(pt_hexa,16))[2:].zfill(64)
    #key in hexadecimal
    key_hexa='0f1571c947d9e859'
    print("Key:",key_hexa)
    #key in binary
    key_bin=bin(int(key_hexa,16))[2:].zfill(64)
    ip_box(pt_bin)
    pt_split(pt_bin_ip_box)
    pc1(key_bin)
    key_split(key_bin_pc1)
    print("Left      Right       Key")
    for i in range(16):
        exp_box(pt_right)
        if(i==0 or i==1 or i==8 or i==15):
            lcs(key_left,key_right)
        else:
            lcs(key_left,key_right)
            key_left = key_left_lcs
            key_right = key_right_lcs
            lcs(key_left,key_right)
        pc2(key_lcs)
        xor_pt_key(pt_right_exp,round_key)
        s_box(xor_pt_key_res)
        straight_p_box(s_box_res)
        xor_Pt_left_straight_p_box_res(pt_left,straight_p_box_res)
        if(i!=15):
            pt_left = pt_right
            pt_right = xor_Pt_left_straight_p_box_res_res
            key_left = key_left_lcs
            key_right = key_right_lcs
        else:
            pt_left = xor_Pt_left_straight_p_box_res_res
            pt_right = pt_right
            key_left = key_left_lcs
            key_right = key_right_lcs
        #values of pt_left,pt_right,key_hexa for next round
        print(format(int(pt_left,2),'x'),end=' ')
        print(format(int(pt_right,2),'x'),end=' ')
        print(format(int(round_key,2),'x'))
    #plaintext after performing 16 times of round function
    final_pt = pt_left + pt_right
    fp_box(final_pt)