from gensim.models.doc2vec import Doc2Vec, TaggedDocument
from nltk.tokenize import word_tokenize
from urllib.parse import unquote

import pandas as pd
import numpy as np
import pickle

model = Doc2Vec.load('/Users/berat/Documents/Projects/XSS-Detector-ML/xss/models/doc2vec.mdl')

def getVec(text):
    features = []
    for i, line in enumerate(text):
        test_data = word_tokenize(line.lower())
        v1 = model.infer_vector(doc_words=test_data)
        #print("V1_infer", v1)
        featureVec = v1
        #print(featureVec)
        lineDecode = unquote(line)
        lowerStr = str(lineDecode).lower()
        #print("X "+str(i)+"=> "+lowerStr)
        # add feature for malicious tag count
        feature1 = int(lowerStr.count('link'))
        feature1 += int(lowerStr.count('object'))
        feature1 += int(lowerStr.count('form'))
        feature1 += int(lowerStr.count('embed'))
        feature1 += int(lowerStr.count('ilayer'))
        feature1 += int(lowerStr.count('layer'))
        feature1 += int(lowerStr.count('style'))
        feature1 += int(lowerStr.count('applet'))
        feature1 += int(lowerStr.count('meta'))
        feature1 += int(lowerStr.count('img'))
        feature1 += int(lowerStr.count('iframe'))
        feature1 += int(lowerStr.count('marquee'))
        # add feature for malicious method count
        feature2 = int(lowerStr.count('exec'))
        feature2 += int(lowerStr.count('fromcharcode'))
        feature2 += int(lowerStr.count('eval'))
        feature2 += int(lowerStr.count('alert'))
        feature2 += int(lowerStr.count('getelementsbytagname'))
        feature2 += int(lowerStr.count('write'))
        feature2 += int(lowerStr.count('unescape'))
        feature2 += int(lowerStr.count('escape'))
        feature2 += int(lowerStr.count('prompt'))
        feature2 += int(lowerStr.count('onload'))
        feature2 += int(lowerStr.count('onclick'))
        feature2 += int(lowerStr.count('onerror'))
        feature2 += int(lowerStr.count('onpage'))
        feature2 += int(lowerStr.count('confirm'))
        # add feature for ".js" count
        feature3 = int(lowerStr.count('.js'))
        # add feature for "javascript" count
        feature4 = int(lowerStr.count('javascript'))
        # add feature for length of the string
        feature5 = int(len(lowerStr))
        # add feature for "<script"  count
        feature6 = int(lowerStr.count('script'))
        feature6 += int(lowerStr.count('<script'))
        feature6 += int(lowerStr.count('&lt;script'))
        feature6 += int(lowerStr.count('%3cscript'))
        feature6 += int(lowerStr.count('%3c%73%63%72%69%70%74'))
        # add feature for special character count
        feature7 = int(lowerStr.count('&'))
        feature7 += int(lowerStr.count('<'))
        feature7 += int(lowerStr.count('>'))
        feature7 += int(lowerStr.count('"'))
        feature7 += int(lowerStr.count('\''))
        feature7 += int(lowerStr.count('/'))
        feature7 += int(lowerStr.count('%'))
        feature7 += int(lowerStr.count('*'))
        feature7 += int(lowerStr.count(';'))
        feature7 += int(lowerStr.count('+'))
        feature7 += int(lowerStr.count('='))
        feature7 += int(lowerStr.count('%3C'))
        # add feature for http count
        feature8 = int(lowerStr.count('http'))
        
        # append the features
        featureVec = np.append(featureVec,feature1)
        featureVec = np.append(featureVec,feature2)
        featureVec = np.append(featureVec,feature3)
        featureVec = np.append(featureVec,feature4)
        featureVec = np.append(featureVec,feature5)
        featureVec = np.append(featureVec,feature6)
        featureVec = np.append(featureVec,feature7)
        featureVec = np.append(featureVec,feature8)
        #print(featureVec)
        features.append(featureVec)
        #print(features)
    return features

classifiers = []

classifiers.append(['Decision Tree', pickle.load(open('/Users/berat/Documents/Projects/XSS-Detector-ML/xss/models/decision_tree.mdl', 'rb'))])
classifiers.append(['Random Forest', pickle.load(open('/Users/berat/Documents/Projects/XSS-Detector-ML/xss/models/random_forest.mdl', 'rb'))])
classifiers.append(['Logistic Regression', pickle.load(open('/Users/berat/Documents/Projects/XSS-Detector-ML/xss/models/logistic_regression.mdl', 'rb'))])
# classifiers.append(['Naive Bayes', pickle.load(open('/Users/berat/Documents/Projects/XSS-Detector-ML/xss/models/naive_bayes.mdl', 'rb'))])
classifiers.append(['KNN', pickle.load(open('/Users/berat/Documents/Projects/XSS-Detector-ML/xss/models/knn.mdl', 'rb'))])
classifiers.append(['MLP', pickle.load(open('/Users/berat/Documents/Projects/XSS-Detector-ML/xss/models/mlp.mdl', 'rb'))])
classifiers.append(['SVM', pickle.load(open('/Users/berat/Documents/Projects/XSS-Detector-ML/xss/models/svm.mdl', 'rb'))])

def checkQueryParams(query):
    check = True
    for [name, c] in classifiers:
        check = check and (c.predict(getVec([query]))[0])
    return check

if __name__ == "__main__":
    import sys
    n = len(sys.argv)
    sys.argv[1] = "--xss_detection"
    for i in range(2, n):
        if checkQueryParams(sys.argv[i]):
            print(" reject", end=" ")	
        else:
            print(" accept", end=" ")	
    sys.exit(0)