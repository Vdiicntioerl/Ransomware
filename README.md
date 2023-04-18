# Réponses TD Ransomware Victor DINIEL a.k.a Arthur


## Question 1 : L'algorithme présent dans xorcrypt s'appelle chiffre de Vernam. L'algorithme est très robuste car la clef a la même taille que le message et est parfaitement aléatoire. Cependant, le code est difficile à mettre en place.

## Question 2 : Si on hache tout de suite la clé, on ne pourrait pas manipuler entre temps.

## Question 3 : On vérifie si il y a un token pour éviter de l'effacer, ce qui peut entraîner des erreurs d'authentification

## Question 4 : On prend la clé envoyée, et on la dérive avec le sel de la même facon qu'on l'a fait pour le token. Si le token correspond à celui stocké dans token.bin, alors on a la bonne cle.

