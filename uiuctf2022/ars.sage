# ars
# uiuctf{bru4e_f0rc3_1s_FUn_fuN_Fun_f0r_The_whOLe_F4miLY!}

factors = [#2,
 #2,
 #3,
 #3,
 #5,
 #5,
 #7,
 #7,
 #11,
 13923226921736843531,
 15789155524315171763,
 10357495682248249393,
 10441209995968076929,
 10476183267045952117,
 11157595634841645959,
 11865228112172030291,
 12775011866496218557,
 13403263815706423849,
 14497899396819662177,
 14695627525823270231,
 16070004423296465647,
 16303174734043925501,
 16755840154173074063,
 17757525673663327889,
 18318015934220252801]

e = 65537
d = 195285722677343056731308789302965842898515630705905989253864700147610471486140197351850817673117692460241696816114531352324651403853171392804745693538688912545296861525940847905313261324431856121426611991563634798757309882637947424059539232910352573618475579466190912888605860293465441434324139634261315613929473
ct = 212118183964533878687650903337696329626088379125296944148034924018434446792800531043981892206180946802424273758169180391641372690881250694674772100520951338387690486150086059888545223362117314871848416041394861399201900469160864641377209190150270559789319354306267000948644929585048244599181272990506465820030285

a = [2, 3, 5, 7, 11]
b = [2, 3, 5 ,7]

from itertools import combinations
from tqdm import tqdm
for combo in tqdm(combinations(factors, 8)):
    r = list(combo)
    a_ = prod(a + r)
    b_ = prod(b + list(set(factors) - set(r)))
    n = (a_+1)*(b_+1)
    try:
        f =  bytes.fromhex(hex(pow(ct,d,n))[2:])
    except:
        continue
    if b'uiuctf' in f:
        print(f)
