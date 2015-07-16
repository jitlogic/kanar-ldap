(ns kanar.ldap
  "LDAP authentication and principal resolve."
  (:require
    [clj-ldap.client :as ldap]
    [slingshot.slingshot :refer [throw+]]
    [kanar.core :as kc]))


(defn ldap-authenticator [ & {:keys [conn base query-str user-re] :or {:user-re #"\W+"}}]
  (fn [_ {{username :username password :password} :params}]
    (if (re-matches user-re username)
      (let [entries (ldap/search conn base {:attributes [:dn] :filter (format query-str username)})]
        (cond
          (empty? entries)
            (throw+ {:type :login-failed, :error "Invalid username or password."})
          (not (empty? (next entries)))
            (throw+ {:type :fatal-error, :error "Error in account database. Please report to administrator."})
          :else
          (let [dn (:dn (first entries))]
            (if (ldap/bind? conn dn password)
              ; TODO analyze various cases here: account blocked, password expired etc.
              {:id username :dn dn :attributes {}}
              (throw+ {:type :login-failed, :error "Invalid username or password."})))
          ))
      (throw+ {:type :login-failed :error "Invalid username or password."})
      ; TODO log this to security log
      )))


(defn ldap-attr-resolver [ & {:keys [conn base attr-map]}]
  (fn [{:keys [id dn]} _]
    (let [entries (ldap/search conn base {:attributes (vec (keys attr-map))})]
      (cond
        (empty? entries)
          (throw+ {:type :fatal-error, :error "Cannot resolve user data."})
        (not (empty? (next entries)))
          (throw+ {:type :fatal-error, :error "Error in account database. Please report to administrator."})
        ; TODO log this as error and send to admin)
        :else
        {:id id
         :attrs
             (let [entry (first entries)]
               (into {} (for [[k1 k2] attr-map] {k2 (k1 entry)})))})
      )))

(defn ldap-group-resolver [ & {:keys [conn u-base g-base]}]

  )
; TODO recursive LDAP group resolver;

