# Composants tiers embarqués

Ocular embarque les composants ci-dessous. Ils sont distribués **sous leur
propre licence**, pas sous la LGPL v3 d'Ocular. La LGPL v3 s'applique au code
propre au projet ; rien ici ne la leur substitue.

Ces composants sont volontairement **embarqués** (`vendor/`) plutôt que
récupérés à l'exécution : le panneau interactif doit fonctionner sans réseau
sortant vers un CDN, et une politique de sécurité de contenu stricte interdit
de toute façon les hôtes externes.

## noVNC

- **Emplacement** : `web/ui/vendor/novnc/`
- **Licence** : Mozilla Public License 2.0 (MPL-2.0)
- **Texte** : [`web/ui/vendor/novnc/LICENSE.txt`](web/ui/vendor/novnc/LICENSE.txt)
- **Amont** : <https://github.com/novnc/noVNC>
- **Version** : ≥ 1.5.0 (le décodeur `h264.js` est présent)
- **Copyright** : The noVNC authors

La MPL-2.0 est un copyleft **par fichier** : un fichier noVNC modifié reste sous
MPL-2.0 et sa source modifiée doit être fournie. Les fichiers embarqués ici sont
**non modifiés** ; leurs en-têtes de licence d'origine sont intacts. Toute
modification future d'un de ces fichiers doit conserver son en-tête et rester
sous MPL-2.0.

La MPL-2.0 est compatible avec une distribution combinée sous (L)GPL v3 : sa
section 3.3 autorise explicitement cette combinaison, chaque composant restant
sous sa propre licence.

## pako

- **Emplacement** : `web/ui/vendor/novnc/vendor/pako/`
- **Licence** : MIT
- **Texte** : [`web/ui/vendor/novnc/vendor/pako/LICENSE`](web/ui/vendor/novnc/vendor/pako/LICENSE)
- **Amont** : <https://github.com/nodeca/pako>
- **Version** : fork ES6 de pako 1.0.3, tel que distribué par noVNC
- **Copyright** : Vitaly Puzrin et Andrey Tupitsin

Il s'agit de la copie que noVNC embarque lui-même — parties inutilisées retirées
et support des tableaux non typés supprimé (voir le `README.md` du répertoire).

---

## Note de conformité

Les fichiers de licence de ces deux composants **manquaient** dans la copie
embarquée : les en-têtes noVNC renvoient à un `LICENSE.txt` qui n'était pas
distribué avec le code. La MPL-2.0 (§3.1) et la licence MIT exigent l'une comme
l'autre que leur texte accompagne le source redistribué. Les deux fichiers ont
été récupérés depuis l'amont et ajoutés avant toute publication.

Toute mise à jour de ces composants doit **reprendre le fichier de licence en
même temps que le code**, et mettre à jour les versions indiquées ci-dessus.
