(ns kanar.ldap
  "LDAP authentication and principal resolve."
  (:require
    [clj-ldap.client :as ldap]
    [slingshot.slingshot :refer [try+ throw+]]
    [kanar.core.util :as ku]
    [taoensso.timbre :as log]))


(def edir-err-defs
  [[#"NDS error.*197.*" {:type :login-failed :msg "Account locked."}]
   [#"NDS error.*215.*" {:type :chpass-failed :msg "Password previously used."}]
   [#"NDS error.*220.*", {:type :login-failed :msg "Account expired."}]
   [#"NDS error: bad password ..222.", {:type :login-failed, :msg "Login failed."}]
   [#"NDS error.*222.*" {:type :login-failed :msg "Password expired."}]
   [#"NDS error: failed authentication ..669." :msg "Login failed."]
   ;[#"NDS error.*669.*" {:type :chpass-failed :msg "Wrong password."}]
   [#".*" {:type :login-failed :msg "Login failed." }]])


(def msad-err-defs
  [[#".*error, data 530.*" {:type :login-failed :msg "Not permitted at this time."}]
   [#".*error, data 532.*" {:type :login-failed :msg "Password expired."}]
   [#".*error, data 533.*" {:type :login-failed :msg "Account disabled."}]
   [#".*error, data 701.*" {:type :login-failed :msg "Account expired."}]
   [#".*error, data 701.*" {:type :login-failed :msg "Password must be reset."}]
   [#".*error, data 775.*" {:type :login-failed :msg "Account locked."}]
   [#".*" {:type :login-failed :msg "Login failed." }]])


(defn dispatch-error [err-defs e]
  (doseq [[rex exc] err-defs]
    (if (re-matches rex (.getMessage e))
      (throw+ exc)))
  (ku/login-failed "Login failed."))


(defn ldap-bind [ldap-conf err-defs dn password]
  (try+
    (let [conn (ldap/connect (assoc ldap-conf :num-connections 1 :bind-dn dn :password password))]
      (log/debug "Successfully bound as " dn)
      (.close conn))
    (catch Exception e
      (log/warn "Error binding user account " e)
      (dispatch-error err-defs e))))


(defn ldap-lookup-dn [conn {:keys [base-dn user-query user-re] :or {:user-re #"\W+"}} id]
  (if (re-matches user-re id)
    (let [query (format user-query id)
          entries (ldap/search conn base-dn {:attributes [:dn] :filter query})]
      (log/debug "Query=" query "results=" entries)
      (cond
        (empty? entries) (ku/login-failed "Invalid username or password.")
        (not (empty? (next entries))) (ku/fatal-error "Error in users database. Please contact administrator.")
        :else (:dn (first entries))))
    (ku/login-failed "Invalid user name.")))


(defn ldap-auth-fn [conn ldap-conf err-defs]
  (fn [_ {{username :username password :password} :params}]
    (let [dn (ldap-lookup-dn conn ldap-conf username)]
      (log/info "Found user DN: " dn)
      (ldap-bind ldap-conf err-defs dn password)
      {:id username :dn dn :attributes {}})))


(defn ldap-lookup-fn [conn ldap-conf]
  (fn [{id :id :as princ} _]
    (let [dn (ldap-lookup-dn conn ldap-conf id)]
      (log/info "Found user DN: " dn)
      (assoc princ :dn dn))))


(defn ldap-attr-fn [conn attr-map]
  (fn [{:keys [dn attributes] :as princ} _]
    (let [entry (ldap/get conn dn (keys attr-map))]
      (if entry
        (assoc princ
          :attributes
          (into (or attributes {}) (for [[k1 k2] attr-map] {k2 (k1 entry)})))
        (ku/login-failed "Cannot obtain user data.")))))


(defn ldap-roles-fn [conn attr to-attr regex]
  (fn [princ _]
    (let [entry (ldap/get conn (:dn princ) [attr])]
      (if entry
        (assoc-in
          princ [:attributes :roles]
          (filterv not-empty
                   (for [g (attr entry)] (second (re-find regex g)))))
        (ku/login-failed "Cannot obtain user data.")))))

; TODO recursive LDAP group resolver

