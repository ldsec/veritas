import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns


# Average the dataframes
def averageDict(input):
    keys = list(input.keys())
    num = len(keys)
    resdict = {}
    for expe in input[str(keys[0])]:
        tmp = {}
        for val in input[str(keys[0])][expe]:
            if val in ['Type', 'PN', 'LogT', 'Lbd']:
                tmp[val] = input[str(keys[0])][expe][val]
            else:
                tmp[val] = 0 
        resdict[expe] = tmp
    
    for i in range(0, len(keys)):
        for expe in resdict:
            resdict[expe]['Ecd'] += float(input[str(keys[i])][expe]['Ecd'])/float(num)
            resdict[expe]['Enc'] += input[str(keys[i])][expe]['Enc']/float(num)
            resdict[expe]['Eval'] += input[str(keys[i])][expe]['Eval']/float(num)
            resdict[expe]['PreVerif'] += input[str(keys[i])][expe]['PreVerif']/float(num)
            resdict[expe]['Verif'] += input[str(keys[i])][expe]['Verif']/float(num)
            resdict[expe]['Dec'] += input[str(keys[i])][expe]['Dec']/float(num)
            resdict[expe]['Dcd'] += input[str(keys[i])][expe]['Dcd']/float(num)
            
    return resdict


# Create relative dictionary
def createDFDiff(input):
    dictionary = {}
    stage = ['Ecd', 'Enc', 'Eval', 'PreVerif', 'Verif', 'Dec', 'Dcd']
    # init dictionary
    for step in stage:
        locdict = {}
        for exp in input:
            if exp != 'Bench':
                locdict[('Create', exp)] = 0
                locdict[('Eval.', exp)] = 0
                locdict[('Verify', exp)] = 0
        dictionary[step] = locdict
        
    for step in stage:
        locdict = {}
        for exp in input:
            if (step in ['Ecd', 'Enc', 'PreVerif'])&(exp != 'Bench'):
                dictionary[step][('Create', exp)] = (input[exp][step] - input['Bench'][step])
            elif (step in ['Eval'])&(exp != 'Bench'):
                dictionary[step][('Eval.', exp)] = (input[exp][step] - input['Bench'][step])
            elif (step in ['Dcd', 'Dec', 'Verif'])&(exp != 'Bench'):
                dictionary[step][('Verify', exp)] = (input[exp][step] - input['Bench'][step])
            else:
                continue
    return dictionary



# Create relative dictionary
def createDFDiffR(input):
    dictionary = {}
    stage = ['Ecd', 'Enc', 'Eval', 'Dec', 'Verif', 'Dcd']
    # init dictionary
    for step in stage:
        locdict = {}
        for exp in input:
            if exp != 'Bench':
                if exp not in ['ReQ', 'PP']: ## Remove here is want to plot the ReQ and PP at create
                    locdict[('Create', exp)] = 0
                if exp not in ['RE+']: ## Remove here is want to plot the ReQ and PP at create    
                    locdict[('Eval.', exp)] = 0
                locdict[('Verify', exp)] = 0
        dictionary[step] = locdict
        
    for step in stage:
        locdict = {}
        for exp in input:
            if (step in ['Ecd', 'Enc'])&(exp not in ['Bench', 'ReQ', 'PP']):  ## Remove here is want to plot the ReQ and PP at create -- just leave Bench
                try:
                    dictionary[step][('Create', exp)] = max(0, input[exp][step] - input['Bench'][step])/(input['Bench']['Ecd']+input['Bench']['Enc'])
                except:
                    continue
            elif (step in ['Eval'])&(exp not in ['Bench', 'RE+']): ## Remove here is want to plot the RE+ at eval -- just leave Bench  
                dictionary[step][('Eval.', exp)] = max(0, input[exp][step] - input['Bench'][step])/(input['Bench']['Eval'])
            elif (step in ['Dcd', 'Dec', 'Verif'])&(exp != 'Bench'):
                try:
                    dictionary[step][('Verify', exp)] = max(0, input[exp][step] - input['Bench'][step])/(input['Bench']['Dcd']+input['Bench']['Dec']+input['Bench']['Verif'])
                except:
                    continue
            else:
                continue
    return dictionary



# Plot the function 
def plot_function(x, ax, datafr):
    #ax = graph[x]
    # x is Create, Eval., Verif.
    ax.set_xlabel(x, weight='bold')
    #ax.tick_params(axis='both', which='both', length=0)
    plot = datafr.xs(x).plot(kind='bar', stacked='True', ax=ax, legend=False)
    #plot.tick_params(pad=0)
    #ax.xticks(ha='right')
    for tick in plot.get_xticklabels():
        tick.set_rotation(45)
    return plot

def plot_functionVal(x, ax, datafr):
    #ax = graph[x]
    # x is Create, Eval., Verif.
    ax.set_xlabel(x, weight='bold')
    #ax.tick_params(axis='both', which='both', length=0)
    plot = datafr.xs(x).plot(kind='bar', stacked='True', ax=ax, legend=False)
    for bars in ax.containers:
        ax.bar_label(bars)
    #plot.tick_params(pad=0)
    #ax.xticks(ha='right')
    for tick in plot.get_xticklabels():
        tick.set_rotation(45)
    return plot


# Plot the function 
def plot_log_function(x, ax, datafr):
    #ax = graph[x]
    ax.set_xlabel(x, weight='bold')
    #ax.tick_params(axis='both', which='both', length=0)
    ax.set_yscale('log')
    plot = datafr.xs(x).plot(kind='bar', stacked='True', ax=ax, legend=False)
    for tick in plot.get_xticklabels():
        tick.set_rotation(45)
    return plot


# Create the grouped dictionary 
def createDF(input):
    dictionary = {}
    stage = ['Ecd', 'Enc', 'Eval', 'PreVerif', 'Verif', 'Dec', 'Dcd']
    # init dictionary
    for step in stage:
        locdict = {}
        for exp in input:
            locdict[('Create', exp)] = 0
            locdict[('Eval.', exp)] = 0
            locdict[('Verify', exp)] = 0
        dictionary[step] = locdict
            
    for step in stage:
        for exp in input:
            if step in ['Ecd', 'Enc', 'PreVerif']:
                dictionary[step][('Create', exp)] = input[exp][step]/1000000000
            elif step in ['Eval']:
                dictionary[step][('Eval.', exp)] = input[exp][step]/1000000000
            elif step in ['Dcd', 'Dec', 'Verif']:
                dictionary[step][('Verify', exp)] = input[exp][step]/1000000000
            else:
                print("error")
    return dictionary



def createTable(input):
    dictionary = {'Create':{}, 'Eval.':{}, 'Verify':{}}
    stage = ['Ecd', 'Enc', 'Eval', 'PreVerif', 'Verif', 'Dec', 'Dcd']
    
    # init dictionary
    tabstring = "\\begin{tabular}{ L{0.8cm}|C{.8cm}|"
    expList = [] 
    string = " & {} "
    string_num = " & {} "
    
    for exp in input:
        tabstring += "C{.8cm}"
        string     += "& {} "
        string_num += "& {:.2f} "
        expList.append(exp)
        dictionary['Create'][exp] = 0
        dictionary['Eval.'][exp] = 0
        dictionary['Verify'][exp] = 0
    tabstring += '}'
        
    for step in stage:
        for exp in input:
            if step in ['Ecd', 'Enc', 'PreVerif']:
                dictionary['Create'][exp] += input[exp][step]
            elif step in ['Eval']:
                dictionary['Eval.'][exp] += input[exp][step]
            elif step in ['Dcd', 'Dec', 'Verif']:
                dictionary['Verify'][exp] += input[exp][step]
            else:
                print("error")
    
    string     += "\\\\"
    string_num += "\\\\"

    header = list(dictionary['Create'].keys())
    header.insert(0, 'stage')
    print(tabstring)
    print(string.format(*header))
    print("\\hline")
    for key in dictionary:
        keyList = list(dictionary[key].values())
        keyList.insert(0, key)
        print(string_num.format(*keyList))   
    print("\end{tabular}")
    return dictionary



def createTableDiff(input):
    dictionary = {'Create':{}, 'Eval.':{}, 'Verify':{}}
    stage = ['Ecd', 'Enc', 'Eval', 'PreVerif', 'Verif', 'Dec', 'Dcd']
    
    # init dictionary
    tabstring = "\\begin{tabular}{ L{0.8cm}|C{.8cm}|"
    expList = [] 
    string = ' & {} '
    string_num = ' & {} '
    
    for exp in input:
        if exp!='Bench':
            tabstring += "C{.8cm}"
            string     += '& {} '
            string_num += '& {:.2f} '
            expList.append(exp)
            dictionary['Create'][exp] = 0
            dictionary['Eval.'][exp] = 0
            dictionary['Verify'][exp] = 0
    tabstring += '}'
        
    for step in stage:
        for exp in input:
            if (step in ['Ecd', 'Enc', 'PreVerif'])&(exp!='Bench'):
                dictionary['Create'][exp] += input[exp][step] - input['Bench'][step]
            elif (step in ['Eval'])&(exp!='Bench'):
                dictionary['Eval.'][exp] += input[exp][step] - input['Bench'][step]
            elif (step in ['Dcd', 'Dec', 'Verif'])&(exp!='Bench'):
                dictionary['Verify'][exp] += input[exp][step] - input['Bench'][step]
            else:
                continue
    
    string     += "\\\\"
    string_num += "\\\\"
   
    header = list(dictionary['Create'].keys())
    header.insert(0, 'stage')
    print(tabstring)
    print(string.format(*header))
    print("\\hline")
    for key in dictionary:
        keyList = list(dictionary[key].values())
        keyList.insert(0, key)
        print(string_num.format(*keyList))
    print("\end{tabular}")  
    return dictionary