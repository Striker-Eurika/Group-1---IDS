import numpy as np
from tensorflow import keras
import tensorflow as tf
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn import metrics
from tensorflow.keras.models import Sequential, load_model
from tensorflow.keras.layers import Dense
from sklearn.metrics import accuracy_score
from sklearn import preprocessing
from sklearn.preprocessing import MinMaxScaler

tf.config.list_physical_devices('GPU')

df = pd.read_csv('NewMachineLearningLabels.csv')
df = df.rename(columns=lambda x: x.strip())

print(df.columns.values)
df.drop('Unnamed: 0', axis=1, inplace=True)
df.head()

#df2 = pd.read_csv('predictThis.csv')
label_encoder = preprocessing.LabelEncoder()

df['Label']= label_encoder.fit_transform(df['Label'])
#df['Label'].unique()

y = df[['Label']]
#print(y)

x = pd.get_dummies(df.drop(['Label', ], axis = 1))
sc = MinMaxScaler()

x = sc.fit_transform(x)
x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.30, random_state=42)
X = pd.DataFrame(x_train)

model = Sequential()

model.add(tf.keras.Input(shape=len(X.columns,)))                     # input layer
model.add(Dense(32, activation='relu'))
model.add(Dense(16, activation='relu'))
model.add(Dense(15, activation='softmax'))

model.compile(loss='sparse_categorical_crossentropy', optimizer='adam', metrics='accuracy')

model.fit(x_train, y_train, epochs=100, batch_size=512)
y_test_pred = model.predict(x_test)
#print(y_test_pred)

model.save("mymodel.h5")
saved_model = keras.models.load_model("mymodel.h5")
y_test_pred = saved_model.predict(x_test)

pred_class = np.argmax(y_test_pred, axis=-1)
#print(pred_class)
print('Accuracy score: ', accuracy_score(y_test, pred_class))
#model.summary()

# RUNNING SOME PREDICTIONS

# ACCURATE ENOUGH. ~89% ACCURACY.
# SEEMS TO PREFER PORTSCANS FOR CERTAIN TCP FLAGS...

new_data = pd.read_csv('monitor_data0.csv')
new_data = pd.DataFrame(new_data)
new_data.head()


new_data.drop('Unnamed: 0', axis=1, inplace=True)

saved_model = keras.models.load_model("mymodel.h5")

sc = MinMaxScaler()
x = pd.get_dummies(new_data)
x = sc.fit_transform(x)

fit_new_input = sc.transform(new_data)
print(fit_new_input)
pred = saved_model.predict(fit_new_input)
print(pred)
pred_class = np.argmax(pred, axis=-1)
print(pred_class)

predict = label_encoder.inverse_transform(pred_class)
predict
