from gensim.models.doc2vec import Doc2Vec, TaggedDocument
from nltk.tokenize import word_tokenize
from urllib.parse import unquote

from sklearn import model_selection
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.svm import SVC
from gensim.models.doc2vec import Doc2Vec, TaggedDocument

import pandas as pd
import numpy as np
import pickle

model = Doc2Vec.load("../models/doc2vec.mdl")

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

classifiers.append(['Decision Tree',DecisionTreeClassifier(random_state=42)])
classifiers.append(['Random Forest',RandomForestClassifier(random_state=42)])
classifiers.append(['Logistic Regression',LogisticRegression(random_state=42)])
classifiers.append(['Naive Bayes',GaussianNB()])
classifiers.append(['KNN',KNeighborsClassifier(n_neighbors=25)])
classifiers.append(['MLP',MLPClassifier(max_iter=2000, random_state=42)])
classifiers.append(['SVM',SVC(kernel='linear', random_state=42)])

read_csv = pd.read_csv('../dataset/XSS_dataset.csv')

X_train, X_test, y_train, y_test = model_selection.train_test_split(read_csv['Sentence'], read_csv['Label'], test_size=0.4, random_state=42)

X_new = getVec(X_train)
X_newtest = getVec(X_test)

for [name, classifier] in classifiers:
    classifier.fit(X_new, y_train)
    y_pred = classifier.predict(X_newtest)
    print(name)
    print(accuracy_score(y_test, y_pred))
    print(confusion_matrix(y_test, y_pred))
    print(classification_report(y_test, y_pred, zero_division=0))
    print("\n")
    savefíle = name.replace(" ","_").lower()+".mdl"
    save_classifier = open('../models/'+savefíle, 'wb')
    pickle.dump(classifier, save_classifier)
    save_classifier.close()



