
def strToIntTuple(data):
    STEP = 4
    res = []
    if len(data) < STEP*STEP:
        return
    else:
        for i in range(0,STEP):
            leftStop = i*STEP
            res[i] = data[leftStop:leftStop + STEP]
    return res
